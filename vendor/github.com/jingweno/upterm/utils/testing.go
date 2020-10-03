package utils

import (
	"fmt"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
)

func WaitForServer(addr string) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	count := 0

	for range ticker.C {
		log.WithField("addr", addr).Info("waiting for server")
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			count++
			if count >= 10 {
				return fmt.Errorf("waiting for addr %s failed", addr)
			}
			continue
		}

		conn.Close()
		break
	}

	return nil
}
