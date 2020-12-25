// This file was adapted from govmomi/toolbox's service.go.
// The original copyright notice follows.

/*
Copyright (c) 2017 VMware, Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nanotoolbox

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"sync"
	"time"
)

const (
	// TOOLS_VERSION_UNMANAGED as defined in open-vm-tools/lib/include/vm_tools_version.h
	toolsVersionUnmanaged = 0x7fffffff

	// RPCIN_MAX_DELAY as defined in rpcChannelInt.h:
	maxDelay = 100 * time.Millisecond

	// If we have an RPCI send error, the channels will be reset.
	// open-vm-tools/lib/rpcChannel/rpcChannel.c:RpcChannelCheckReset also backs off in this case
	resetDelay = 5 * time.Second
)

// Service receives and dispatches incoming RPC requests from the vmx
type Service struct {
	Log *log.Logger
	Out *ChannelOut

	in       Channel
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

// NewService initializes a Service instance
func NewService(rpcIn Channel, rpcOut Channel) *Service {
	s := &Service{
		Log: log.New(ioutil.Discard, "", 0),
		Out: &ChannelOut{rpcOut},
		in:  rpcIn,

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

	// Without tools.set.version, the UI reports Tools are "running", but "not installed"
	s.AddCapability(fmt.Sprintf("tools.set.version %d", toolsVersionUnmanaged))

	return s
}

// backoff exponentially increases the RPC poll delay up to maxDelay
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
	_ = s.in.Stop()
	_ = s.Out.Stop()
}

func (s *Service) startChannel() error {
	err := s.in.Start()
	if err != nil {
		return err
	}

	return s.Out.Start()
}

func (s *Service) checkReset() error {
	if s.rpcError {
		s.stopChannel()
		err := s.startChannel()
		if err != nil {
			s.delay = resetDelay
			return err
		}
		s.rpcError = false
	}

	return nil
}

// Start initializes the RPC channels and starts a goroutine to listen for incoming RPC requests
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

				err = s.in.Send(response)
				response = nil
				if err != nil {
					s.delay = resetDelay
					s.rpcError = true
					continue
				}

				request, _ := s.in.Receive()

				if len(request) > 0 {
					response = s.Dispatch(request)
					s.delay = 0
				} else {
					s.backoff()
				}
			}
		}
	}()

	return nil
}

// Stop cancels the RPC listener routine created via Start
func (s *Service) Stop() {
	close(s.stop)
}

// Wait blocks until Start returns, allowing any current RPC in progress to complete.
func (s *Service) Wait() {
	s.wg.Wait()
}

// CommandHandler is given the raw argument portion of an RPC request and returns a response
type CommandHandler func([]byte) ([]byte, error)

// OptionHandler is given the raw key and value of Set_Option requests
type OptionHandler func(key, value string)

func (s *Service) AddCapability(name string) {
	s.capabilities = append(s.capabilities, name)
}

func (s *Service) RegisterCommandHandler(name string, handler CommandHandler) {
	s.commandHandlers[name] = handler
}

func (s *Service) RegisterOptionHandler(key string, handler OptionHandler) {
	s.optionHandlers[key] = handler
}

func (s *Service) RegisterResetHandler(f func()) {
	s.resetHandlers = append(s.resetHandlers, f)
}

// Dispatch an incoming RPC request to a CommandHandler
func (s *Service) Dispatch(request []byte) []byte {
	msg := bytes.SplitN(request, []byte{' '}, 2)
	name := msg[0]

	// Trim NULL byte terminator
	name = bytes.TrimRight(name, "\x00")

	handler, ok := s.commandHandlers[string(name)]

	if !ok {
		s.Log.Printf("[service] unknown command: %q\n", name)
		return []byte("Unknown Command")
	}

	var args []byte
	if len(msg) == 2 {
		args = msg[1]
	}

	response, err := handler(args)
	if err == nil {
		response = append([]byte("OK "), response...)
	} else {
		s.Log.Printf("[service] error calling handler %q: %s\n", name, err)
		response = append([]byte("ERR "), response...)
	}

	return response
}

func (s *Service) HandleReset([]byte) ([]byte, error) {
	for _, f := range s.resetHandlers {
		f()
	}
	return []byte("ATR " + s.name), nil
}

func (s *Service) HandlePing([]byte) ([]byte, error) {
	return nil, nil
}

func (s *Service) HandleSetOption(args []byte) ([]byte, error) {
	opts := bytes.SplitN(args, []byte{' '}, 2)
	key := string(opts[0])
	val := string(opts[1])
	if handler, ok := s.optionHandlers[key]; ok {
		handler(key, val)
	}
	return nil, nil
}

func (s *Service) HandleCapabilitiesRegister([]byte) ([]byte, error) {
	for _, capability := range s.capabilities {
		_, err := s.Out.Request([]byte(capability))
		if err != nil {
			return nil, fmt.Errorf("error sending %q: %s", capability, err)
		}
	}
	return nil, nil
}
