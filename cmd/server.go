package cmd

import (
	"fmt"
	"net/http"
	"os"

	"dkms/server"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	ip            string
	port          string
	privateKeyHex string
	logName       string
	serverCmd     = &cobra.Command{
		Use:   "server",
		Short: "command for server",
	}
	runServerCmd = &cobra.Command{
		Use:   "runserver",
		Short: "command for server",
		Run: func(cmd *cobra.Command, args []string) {
			f, err := os.OpenFile(logName+".log", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
			if err != nil {
				fmt.Printf("error opening file: %v", err)
			}
			defer f.Close()
			s := server.New(ip, port, privateKeyHex,f)
			if err := s.Run(ip + ":" + port); err != nil {
				panic(fmt.Sprintf("failed to run server: %s", err.Error()))
			}
		},
	}
	startCheckerCmd = &cobra.Command{
		Use:   "startChecker",
		Short: "start checker damon for server",
		RunE: func(cmd *cobra.Command, args []string) error {
			url := "http://" + ip + ":" + port + "/checker/start"

			_, err := http.Post(url, "", nil)
			if err != nil {
				logrus.Error(err.Error())
				return err
			}
			return nil
		},
	}
	stopCheckerCmd = &cobra.Command{
		Use:   "stopChecker",
		Short: "stop checker damon for server",
		RunE: func(cmd *cobra.Command, args []string) error {
			url := "http://" + ip + ":" + port + "/checker/stop"
			_, err := http.Post(url, "", nil)
			if err != nil {
				logrus.Error(err.Error())
				return err
			}
			return nil
		},
	}
)

func init() {
	serverCmd.AddCommand(runServerCmd)
	serverCmd.AddCommand(startCheckerCmd)
	serverCmd.AddCommand(stopCheckerCmd)

	runServerCmd.PersistentFlags().StringVar(&ip, "ip", "127.0.0.1", "ip for boot server")
	runServerCmd.PersistentFlags().StringVar(&port, "port", "8000", "port for boot server")
	runServerCmd.PersistentFlags().StringVar(&logName, "log", "", "log file name for server")
	runServerCmd.PersistentFlags().StringVar(&privateKeyHex, "key", "", "private key hex for server")
	_ = runServerCmd.MarkPersistentFlagRequired("key")
	_ = runServerCmd.MarkPersistentFlagRequired("log")

	startCheckerCmd.PersistentFlags().StringVar(&ip, "ip", "127.0.0.1", "ip for boot server")
	startCheckerCmd.PersistentFlags().StringVar(&port, "port", "8000", "port for boot server")
	_ = startCheckerCmd.MarkPersistentFlagRequired("ip")
	_ = startCheckerCmd.MarkPersistentFlagRequired("port")

	stopCheckerCmd.PersistentFlags().StringVar(&ip, "ip", "127.0.0.1", "ip for boot server")
	stopCheckerCmd.PersistentFlags().StringVar(&port, "port", "8000", "port for boot server")
	_ = stopCheckerCmd.MarkPersistentFlagRequired("ip")
	_ = stopCheckerCmd.MarkPersistentFlagRequired("port")
}
