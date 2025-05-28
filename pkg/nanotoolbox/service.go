// This file was adapted from govmomi/toolbox's service.go.
// The original copyright notice follows.

// SPDX-FileCopyrightText: Copyright (c) 2020 Oliver Kuckertz, Siderolabs and Equinix
// SPDX-License-Identifier: Apache-2.0

package nanotoolbox

import (
	"bytes"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/siderolabs/talos-vmtoolsd/internal/util"
)

const (
	// TOOLS_VERSION_UNMANAGED as defined in open-vm-tools/lib/include/vm_tools_version.h.
	toolsVersionUnmanaged = 0x7fffffff

	// RPCIN_MAX_DELAY as defined in rpcChannelInt.h.
	maxDelay = 100 * time.Millisecond

	// If we have an RPCI send error, the channels will be reset.
	// open-vm-tools/lib/rpcChannel/rpcChannel.c:RpcChannelCheckReset also backs off in this case.
	resetDelay = 5 * time.Second
)

// Service receives and dispatches incoming RPC requests from the vmx.
type Service struct { //nolint:govet
	logger *slog.Logger

	tclo *TCLO
	rpci *RPCI

	name     string
	stop     chan struct{}
	wg       *sync.WaitGroup
	delay    time.Duration
	rpcError bool

	resetHandlers   []func()
	commandHandlers map[string]CommandHandler
	optionHandlers  map[string]OptionHandler
	capabilities    []string
}

// NewService initializes a Service instance.
func NewService(log *slog.Logger, r *RPCI, t *TCLO) *Service {
	s := &Service{
		logger: log,
		tclo:   t,
		rpci:   r,

		name: "toolbox", // same name used by vmtoolsd
		wg:   new(sync.WaitGroup),
		stop: make(chan struct{}),

		commandHandlers: make(map[string]CommandHandler),
		optionHandlers:  make(map[string]OptionHandler),
	}

	s.RegisterCommandHandler("reset", s.HandleReset)
	s.RegisterCommandHandler("ping", s.HandlePing)
	s.RegisterCommandHandler("Set_Option", s.HandleSetOption)
	s.RegisterCommandHandler("Capabilities_Register", s.HandleCapabilitiesRegister)

	// Without tools.set.version the UI reports Tools are "running", but "not installed"
	s.AddCapability(fmt.Sprintf("tools.set.version %d", toolsVersionUnmanaged))

	return s
}

// Request wraps ChannelOut.Request for demarcation/protection.
func (s *Service) Request(request []byte) ([]byte, error) {
	util.TraceLog(s.logger, "requesting", "request", request)

	return s.rpci.Request(request)
}

// backoff exponentially increases the RPC poll delay up to maxDelay.
func (s *Service) backoff() {
	if s.delay < maxDelay {
		if s.delay > 0 {
			d := s.delay * 2
			if d > s.delay && d < maxDelay {
				s.delay = d
			} else {
				s.delay = maxDelay
			}
		} else {
			s.delay = 10 * time.Microsecond
		}
	}
}

func (s *Service) stopChannel() {
	s.tclo.Stop() //nolint:errcheck
	s.rpci.Stop() //nolint:errcheck
}

func (s *Service) startChannel() error {
	err := s.tclo.Start()
	if err != nil {
		return err
	}

	return s.rpci.Start()
}

func (s *Service) checkReset() error {
	if s.rpcError {
		s.logger.Warn("resetting because of rpc error", "err", s.rpcError)
		s.stopChannel()

		err := s.startChannel()
		if err != nil {
			s.logger.Error("error restarting channel", "err", err)
			s.delay = resetDelay

			return err
		}

		s.rpcError = false
	}

	return nil
}

// Start initializes the RPC channels and starts a goroutine to listen for incoming RPC requests.
func (s *Service) Start() error {
	err := s.startChannel()
	if err != nil {
		return err
	}

	s.wg.Add(1)

	go func() {
		defer s.wg.Done()

		// Same polling interval and backoff logic as vmtoolsd.
		// Required in our case at startup at least, otherwise it is possible
		// we miss the 1 Capabilities_Register call for example.

		// Note we Send(response) even when nil, to let the VMX know we are here
		var response []byte

		for {
			select {
			case <-s.stop:
				s.stopChannel()

				return
			case <-time.After(s.delay):
				if err = s.checkReset(); err != nil {
					continue
				}

				err = s.tclo.Send(response)
				util.TraceLog(s.logger, "send", "err", err, "response", string(response))
				response = nil

				if err != nil {
					s.logger.Warn("send failed")
					s.delay = resetDelay
					s.rpcError = true

					continue
				}

				request, _ := s.tclo.Receive() //nolint:errcheck
				util.TraceLog(s.logger, "received request", "request", string(request))

				if len(request) > 0 {
					response = s.Dispatch(request)
					util.TraceLog(s.logger, "response from dispatch", "request", string(request), "response", string(response))
					s.delay = 0
				} else {
					util.TraceLog(s.logger, "backing off")
					s.backoff()
				}
			}
		}
	}()

	return nil
}

// Stop cancels the RPC listener routine created via Start.
func (s *Service) Stop() {
	close(s.stop)
}

// Wait blocks until Start returns, allowing any current RPC in progress to complete.
func (s *Service) Wait() {
	s.wg.Wait()
}

// CommandHandler is given the raw argument portion of an RPC request and returns a response.
type CommandHandler func([]byte) ([]byte, error)

// OptionHandler is given the raw key and value of Set_Option requests.
type OptionHandler func(key, value string)

// AddCapability adds a capability to the Service.
func (s *Service) AddCapability(name string) {
	s.logger.Debug("registering capability", "capability", name)
	s.capabilities = append(s.capabilities, name)
}

// RegisterCommandHandler adds a CommandHandler to the Service.
func (s *Service) RegisterCommandHandler(name string, handler CommandHandler) {
	s.logger.Debug("registering command handler", "command", name)
	s.commandHandlers[name] = handler
}

// RegisterOptionHandler adds an OptionHandler to the Service.
func (s *Service) RegisterOptionHandler(key string, handler OptionHandler) {
	s.logger.Debug("registering command handler", "option", key)
	s.optionHandlers[key] = handler
}

// RegisterResetHandler adds a function to be called when the Service is reset.
func (s *Service) RegisterResetHandler(f func()) {
	s.logger.Debug("registering a reset handler")
	s.resetHandlers = append(s.resetHandlers, f)
}

// Dispatch an incoming RPC request to a CommandHandler.
func (s *Service) Dispatch(request []byte) []byte {
	s.logger.Debug("dispatching", "request", string(request))
	msg := bytes.SplitN(request, []byte{' '}, 2)
	name := msg[0]

	// Trim NULL byte terminator
	name = bytes.TrimRight(name, "\x00")
	l := s.logger.With("handler_kind", string(name))

	handler, ok := s.commandHandlers[string(name)]

	if !ok {
		l.Debug("unknown command kind")

		return []byte("ERROR Unknown Command")
	}

	var args []byte
	if len(msg) == 2 {
		args = msg[1]
	}

	response, err := handler(args)
	if err == nil {
		response = append([]byte("OK "), response...)
	} else {
		l.Warn("error calling handler", "err", err)

		response = append([]byte("ERROR "), response...)
	}

	return response
}

// HandleReset resets the Service.
func (s *Service) HandleReset([]byte) ([]byte, error) {
	for _, f := range s.resetHandlers {
		f()
	}

	return []byte("ATR " + s.name), nil
}

// HandlePing responds to a ping request.
func (s *Service) HandlePing([]byte) ([]byte, error) {
	return nil, nil
}

// HandleSetOption handles Set_Option requests.
func (s *Service) HandleSetOption(args []byte) ([]byte, error) {
	opts := bytes.SplitN(args, []byte{' '}, 2)
	key := string(opts[0])
	val := string(opts[1])

	if handler, ok := s.optionHandlers[key]; ok {
		handler(key, val)
	}

	return nil, nil
}

// HandleCapabilitiesRegister sends the Service's capabilities to the vmx.
func (s *Service) HandleCapabilitiesRegister([]byte) ([]byte, error) {
	for _, capability := range s.capabilities {
		_, err := s.Request([]byte(capability))
		if err != nil {
			return nil, fmt.Errorf("error sending %q: %w", capability, err)
		}
	}

	return nil, nil
}
