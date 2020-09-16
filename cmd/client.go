package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"dkms/client"
	"dkms/server/interfaces"
	"dkms/server/types"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

var (
	t int
	u int

	clientCmd = &cobra.Command{
		Use:   "client",
		Short: "command for client",
		Run: func(cmd *cobra.Command, args []string) {

		},
	}

	registerCmd = &cobra.Command{
		Use:   "register [userId] [private key hex] [server address(comma split)]",
		Short: "stop checker damon for server",
		Args:  cobra.MinimumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			addresses := strings.Split(args[2], ",")
			suite := edwards25519.NewBlakeSHA256Ed25519()
			client, err := client.NewClient(args[0], suite, args[1])
			if err != nil {
				return err
			}
			a := make([]types.Address, len(addresses))
			for i, v := range addresses {
				data := strings.Split(v, ":")
				if len(data) != 2 {
					return errors.New("ip:port address required")
				}
				ip, port := data[0], data[1]
				a[i] = types.Address{
					Ip:   ip,
					Port: port,
				}

				logrus.Info("successfully registered at " + v)
			}
			err = client.RegisterKey(a, t, u)
			if err != nil {
				return err
			}
			return nil
		},
	}

	startCheckingCmd = &cobra.Command{
		Use:   "check [user Id] [server address(comma split)]",
		Short: "start checking user in servers checker",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			addresses := strings.Split(args[1], ",")
			for _, oneAddr := range addresses {
				url := "http://" + oneAddr + "/checker/user"
				b, err := json.Marshal(interfaces.AddCheckUserRequest{
					UserId: args[0],
				})
				if err != nil {
					logrus.Info("start checking at " + oneAddr + " failed, " + err.Error())
				}
				_, err = http.Post(url, "application/json", bytes.NewReader(b))
				if err != nil {
					logrus.Info("start checking at " + oneAddr + " failed, " + err.Error())
				} else {
					logrus.Info("start checking at " + oneAddr + " successful")
				}

			}
			return nil
		},
	}

	stopCheckingCmd = &cobra.Command{
		Use:   "uncheck [user Id] [server address(comma split)]",
		Short: "stop checking user in servers checker",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			addresses := strings.Split(args[1], ",")
			for _, oneAddr := range addresses {
				url := "http://" + oneAddr + "/checker/user/delete"

				b, err := json.Marshal(interfaces.RemoveCheckUserRequest{
					UserId: args[0],
				})
				if err != nil {
					logrus.Info("start checking at " + oneAddr + " failed, " + err.Error())
				}
				_, err = http.Post(url, "application/json", bytes.NewReader(b))

				if err != nil {
					logrus.Info("stop checking at " + oneAddr + " failed, " + err.Error())
				} else {
					logrus.Info("stop checking at " + oneAddr + " successful")
				}
			}
			return nil
		},
	}
)

func init() {

	clientCmd.AddCommand(registerCmd)
	clientCmd.AddCommand(startCheckingCmd)
	clientCmd.AddCommand(stopCheckingCmd)

	registerCmd.PersistentFlags().IntVar(&t, "t", 3, "t value for user key")
	registerCmd.PersistentFlags().IntVar(&u, "u", 3, "u value for user key")
}
