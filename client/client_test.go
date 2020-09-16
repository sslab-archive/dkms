package client

import (
	"testing"

	"dkms/node"
	"dkms/share"

	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

func TestRegisterKey(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	clientPrivateKey := suite.Scalar().SetInt64(int64(12345))
	clientPrivateKeyHex, err := share.ScalarToHex(clientPrivateKey)
	assert.NoError(t, err)

	client, err := NewClient("hea9549", suite, clientPrivateKeyHex)
	assert.NoError(t, err)

	addrs := make([]node.Address, 0)
	addrs = append(addrs, node.Address{
		Ip:   "127.0.0.1",
		Port: "8080",
	})
	addrs = append(addrs, node.Address{
		Ip:   "127.0.0.1",
		Port: "8081",
	})
	addrs = append(addrs, node.Address{
		Ip:   "127.0.0.1",
		Port: "8082",
	})

	err = client.RegisterKey(addrs, 3, 3)

	assert.NoError(t, err)
}
