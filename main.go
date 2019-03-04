package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"syscall"

	"github.com/docker/docker/api/types"
	sec "github.com/seccomp/libseccomp-golang"
)

func main() {
	var regs syscall.PtraceRegs
	scalls := make(calls, 303)
	scalls.init()

	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Ptrace: true,
	}

	cmd.Start()
	err := cmd.Wait()
	if err != nil {
		fmt.Println(err)
	}
	pid := cmd.Process.Pid
	exit := true
	for {
		if exit {
			err = syscall.PtraceGetRegs(pid, &regs)
			if err != nil {
				break
			}
			scalls[getName(regs.Orig_rax)] = true
		}

		err = syscall.PtraceSyscall(pid, 0)
		if err != nil {
			panic(err)
		}
		_, err := syscall.Wait4(pid, nil, 0, nil)
		if err != nil {
			panic(err)
		}
		exit = !exit
	}
	generateProfile(scalls)
}

func getName(id uint64) string {
	name, _ := sec.ScmpSyscall(id).GetName()
	return name
}

func generateProfile(c calls) {
	s := types.Seccomp{}
	b, _ := ioutil.ReadFile("default.json")
	json.Unmarshal(b, &s)
	var names []string
	for s, t := range c {
		if t {
			names = append(names, s)
		}
	}
	s.Syscalls = []*types.Syscall{
		&types.Syscall{
			Action: types.ActAllow,
			Names:  names,
			Args:   []*types.Arg{},
		},
	}
	sJSON, _ := json.Marshal(s)

	err := ioutil.WriteFile("output.json", sJSON, 0644)
	if err != nil {
		panic(err)
	}

}
