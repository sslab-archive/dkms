package share

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

func TestScenario(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	privateKey := suite.Scalar().Pick(suite.RandomStream())
	publicKey := suite.Point().Mul(privateKey, nil)

	toBeEncrypted := "나는 해성이당 ㅎㅎ나는 해성이당 ㅎㅎ"
	encryptMsg, err := Encrypt(suite, publicKey, []byte(toBeEncrypted))

	assert.NoError(t, err)
	fmt.Println("raw msg : "+toBeEncrypted)
	fmt.Println("encrypted msg : " + encryptMsg.MsgHex)

	decryptedMsg, err := Decrypt(suite, privateKey, *encryptMsg)
	assert.NoError(t, err)
	fmt.Println("decrypted msg : " + string(decryptedMsg))
}
