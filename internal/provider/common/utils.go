package common

import (
	"fmt"
	"strings"
	"time"
)

func TrimString(data string) string {
	cleaned := strings.Trim(data, "\"")
	return cleaned
}

// logEntryExit is a function that wraps another function to log its entry and exit.
func LogEntryExit(f func() error) func() error {
	return func() error {
		start := time.Now()
		defer func() {
			fmt.Printf("Function executed in %v\n", time.Since(start))
		}()
		fmt.Println("Entering function...")
		err := f()
		fmt.Println("Exiting function...")
		return err
	}
}
