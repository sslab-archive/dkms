package share

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

func GetSamplePoly(suite Suite, secret kyber.Scalar) BiPoly {
	// make B(x,y) = secret + x + 2x^2 + 3y + 4y^2
	xCoeffs := make([]kyber.Scalar, 2)
	yCoeffs := make([]kyber.Scalar, 2)
	xCoeffs[0] = suite.Scalar().SetInt64(int64(1))
	xCoeffs[1] = suite.Scalar().SetInt64(int64(2))
	yCoeffs[0] = suite.Scalar().SetInt64(int64(3))
	yCoeffs[1] = suite.Scalar().SetInt64(int64(4))

	return BiPoly{
		G:       suite,
		Secret:  secret,
		XCoeffs: xCoeffs,
		YCoeffs: yCoeffs,
	}
}
func TestVerifyCommitPhase(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	secret := suite.Scalar().SetInt64(123)
	serverPrivateKey := suite.Scalar().Pick(suite.RandomStream())
	serverPublicKey := suite.Point().Mul(serverPrivateKey, nil)

	poly := GetSamplePoly(suite, secret)
	H := suite.Point().Pick(suite.XOF([]byte("H")))
	commit := poly.Commit(H)

	serverSecretEncrypted := suite.Point().Mul(poly.Eval(2, 2).V, serverPublicKey)

	w := suite.Scalar().SetInt64(int64(300))
	c := suite.Scalar().SetInt64(int64(2))
	r := GenerateRScalar(suite, w, c, poly.Eval(2, 2))

	result := VerifyRScalar(suite, w, c, r, 2, 2, serverPublicKey, commit, serverSecretEncrypted)
	assert.True(t, result)
}

func TestPoly(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	secret := suite.Scalar().SetInt64(123)

	poly := GetSamplePoly(suite, secret)
	xp := poly.GetXPoly(1)
	yp := poly.GetYPoly(2)
	xpv := xp.Eval(2).V
	ypv := yp.Eval(1).V

	assert.True(t, xpv.Equal(ypv))

	assert.True(t, xpv.Equal(poly.Eval(2, 1, ).V))
}

func TestGenPrivateKey(t *testing.T)  {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	for i:=0;i<500;i++{
		pvkey := suite.Scalar().Pick(suite.RandomStream())
		d,err := ScalarToHex(pvkey)
		if err !=nil{
			panic("err")

		}
		fmt.Println(d)
	}
}