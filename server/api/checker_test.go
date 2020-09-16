package api

import (
	"fmt"
	"testing"
	"time"
)

func TestDaemon(t *testing.T) {
	done := make(chan string)
	go func() {

		time.Sleep(time.Second)
		done <- "1"
		time.Sleep(time.Second)
		done <- "1"
		time.Sleep(time.Second)
		done <- "1"
	}()
	for {
		select {
		case r := <-done:
			fmt.Println(r)
		}
	}
}
