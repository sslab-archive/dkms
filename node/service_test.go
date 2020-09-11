package node

import (
	"testing"

	"dkms/share"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

func MakePolynomial() share.BiPoly {

	suite := edwards25519.NewBlakeSHA256Ed25519()
	secret := suite.Scalar().SetInt64(int64(10))

	xCoeffs := make([]kyber.Scalar, 2)
	xCoeffs[0] = suite.Scalar().SetInt64(int64(2))
	xCoeffs[1] = suite.Scalar().SetInt64(int64(3))

	yCoeffs := make([]kyber.Scalar, 2)
	yCoeffs[0] = suite.Scalar().SetInt64(int64(4))
	yCoeffs[1] = suite.Scalar().SetInt64(int64(5))

	poly := share.BiPoly{
		G:       suite,
		Secret:  secret,
		XCoeffs: xCoeffs,
		YCoeffs: yCoeffs,
	}
	return poly
}

func TestService_EncryptedMessageToPoints(t *testing.T) {
	//suite := edwards25519.NewBlakeSHA256Ed25519()
	//keyBinary, err := suite.Scalar().Pick(suite.RandomStream()).MarshalBinary()
	//assert.NoError(t, err)
	//
	//service, err := NewService(suite, keyBinary)
	//assert.NoError(t, err)
	//
	//poly := MakePolynomial()
	//
	//testPoints := make([]BiPoint, 3)
	//testPoints[0] = poly.Eval(1, 1)
	//testPoints[1] = poly.Eval(1, 2)
	//testPoints[2] = poly.Eval(1, 3)
	//
	//typePoints := make([]types.BiPoint, 3)
	//
	//p1, err := testPoints[0].ToTypes()
	//assert.NoError(t, err)
	//p2, err := testPoints[1].ToTypes()
	//assert.NoError(t, err)
	//p3, err := testPoints[2].ToTypes()
	//assert.NoError(t, err)
	//
	//typePoints[0] = *p1
	//typePoints[1] = *p2
	//typePoints[2] = *p3
	//
	//marshaledData, err := json.Marshal(typePoints)
	//assert.NoError(t, err)
	//toBeEncrypted := hex.EncodeToString(marshaledData)
	//
	//encMsg, err := Encrypt(service.Suite, service.GetMyPublicKey(), []byte(toBeEncrypted))
	//assert.NoError(t, err)
	//
	//decPoints, err := service.EncryptedMessageToPoints(*encMsg)
	//assert.NoError(t, err)
	//
	//assert.Equal(t,testPoints,decPoints)

}
