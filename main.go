package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/coreos/go-systemd/sdjournal"
)

type syscallRequest struct {
	syscallNo int64
	pid       int64
	uid       int64
	gid       int64
}

func main() {
	c := make(chan syscallRequest)
	go readJournal(c)

}

func readJournal(c chan syscallRequest) {
	j, err := sdjournal.NewJournal()
	defer j.Close()
	if err != nil {
		fmt.Println(err)
	}
	err = j.AddMatch("_AUDIT_TYPE_NAME=SECCOMP")
	if err := j.SeekRealtimeUsec(uint64(time.Now().UnixNano() / 1000)); err != nil {
		fmt.Println("can't seek")
	}

	if _, err := j.Next(); err != nil {
		fmt.Println(err)
	}
	prevCursor, err := j.GetCursor()
	if err != nil {
		fmt.Println(err)
	}
	for {
		if _, err := j.Next(); err != nil {
			fmt.Println(err)
		}
		newCursor, err := j.GetCursor()
		if err != nil {
			fmt.Println(err)
		}
		if prevCursor == newCursor {
			_ = j.Wait(sdjournal.IndefiniteWait)
			continue
		}
		prevCursor = newCursor
		entry, err := j.GetEntry()
		if err != nil {
			fmt.Println(err)
		}
		c <- convertToSyscallRequest(entry)
	}
}

func convertToSyscallRequest(entry *sdjournal.JournalEntry) syscallRequest {
	uid, _ := strconv.ParseInt(entry.Fields["_UID"], 10, 64)
	gid, _ := strconv.ParseInt(entry.Fields["_GID"], 10, 64)
	pid, _ := strconv.ParseInt(entry.Fields["_PID"], 10, 64)
	sNo, _ := strconv.ParseInt(entry.Fields["_AUDIT_FIELD_SYSCALL"], 10, 64)
	s := syscallRequest{
		syscallNo: sNo,
		pid:       pid,
		gid:       gid,
		uid:       uid,
	}
	return s
}
