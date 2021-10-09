package tboxcmds

import (
	"fmt"
	"github.com/mologie/talos-vmtoolsd/internal/nanotoolbox"
	"github.com/sirupsen/logrus"
)

// vmware/guestrpc/powerops.h
const (
	_ = iota
	PowerStateHalt
	PowerStateReboot
	PowerStatePowerOn
	PowerStateResume
	PowerStateSuspend
)

var powerCmdName = map[int]string{
	PowerStateHalt:    "OS_Halt",
	PowerStateReboot:  "OS_Reboot",
	PowerStatePowerOn: "OS_PowerOn",
	PowerStateResume:  "OS_Resume",
	PowerStateSuspend: "OS_Suspend",
}

type PowerDelegate interface {
	Shutdown() error
	Reboot() error
}

type PowerHandler func() error

type powerOp struct {
	Log     logrus.FieldLogger
	Out     *nanotoolbox.ChannelOut
	State   int
	Handler PowerHandler
}

func (op powerOp) Name() string {
	return powerCmdName[op.State]
}

func (op powerOp) HandleCommand([]byte) ([]byte, error) {
	op.Log.Printf("[cmds/power] handling power operation %v", op.Name())

	rc := nanotoolbox.RpciOK
	if op.Handler != nil {
		if err := op.Handler(); err != nil {
			op.Log.Printf("[cmds/power] error handling %q: %v", op.Name(), err)
			rc = nanotoolbox.RpciERR
		}
	}

	msg := fmt.Sprintf("tools.os.statechange.status %s%d\x00", rc, op.State)
	if _, err := op.Out.Request([]byte(msg)); err != nil {
		return nil, fmt.Errorf("error sending %q: %w", msg, err)
	}

	return nil, nil
}

func powerOpHandler(svc *nanotoolbox.Service, state int, handler PowerHandler) (string, nanotoolbox.CommandHandler) {
	op := powerOp{Log: svc.Log, Out: svc.Out, State: state, Handler: handler}
	return op.Name(), op.HandleCommand
}

func RegisterPowerDelegate(svc *nanotoolbox.Service, delegate PowerDelegate) {
	svc.AddCapability("tools.capability.statechange")
	svc.RegisterCommandHandler(powerOpHandler(svc, PowerStateHalt, delegate.Shutdown))
	svc.RegisterCommandHandler(powerOpHandler(svc, PowerStateReboot, delegate.Reboot))
	svc.RegisterCommandHandler(powerOpHandler(svc, PowerStatePowerOn, nil))
	svc.RegisterCommandHandler(powerOpHandler(svc, PowerStateSuspend, nil))
	svc.RegisterCommandHandler(powerOpHandler(svc, PowerStateResume, nil))
}
