package share

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"go.dedis.ch/kyber/v3/share/pvss"
	"testing"
	"time"

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

func TestVerifyOptCommitPhase(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	secret := suite.Scalar().SetInt64(123)
	serverPrivateKey := suite.Scalar().Pick(suite.RandomStream())
	serverPublicKey := suite.Point().Mul(serverPrivateKey, nil)

	poly := GetSamplePoly(suite, secret)
	H := suite.Point().Pick(suite.XOF([]byte("H")))
	commit := poly.OptCommit(H,2)

	serverSecretEncrypted := suite.Point().Mul(poly.Eval(2, 5).V, serverPublicKey)

	w := suite.Scalar().SetInt64(int64(300))
	c := suite.Scalar().SetInt64(int64(2))
	r := GenerateRScalar(suite, w, c, poly.Eval(2, 5))

	result := VerifyOptRScalar(suite, w, c, r, 2, 5, serverPublicKey, commit, serverSecretEncrypted)
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

	assert.True(t, xpv.Equal(poly.Eval(2, 1).V))
}

func TestGenPrivateKey(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()

	for i := 0; i < 500; i++ {
		pvkey := suite.Scalar().Pick(suite.RandomStream())
		d, err := ScalarToHex(pvkey)
		if err != nil {
			panic("err")

		}
		fmt.Println(d)
	}
}

func TestPVSSBench(t *testing.T) {
	// Benchmark test
	suite := edwards25519.NewBlakeSHA256Ed25519()
	//G := suite.Point().Base()
	H := suite.Point().Pick(suite.XOF([]byte("H")))
	n := 20
	threshold := 10
	x := make([]kyber.Scalar, n) // trustee private keys
	X := make([]kyber.Point, n)  // trustee public keys
	for i := 0; i < n; i++ {
		x[i] = suite.Scalar().Pick(suite.RandomStream())
		X[i] = suite.Point().Mul(x[i], nil)
	}

	secret := suite.Scalar().Pick(suite.RandomStream())

	logrus.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.StampMicro,
	})
	logrus.Info("end distribution and start decryption1")
	// (1) Share distribution (dealer)
	encShares, pubPoly, err := pvss.EncShares(suite, H, X, secret, threshold)
	assert.NoError(t, err)
	sH := make([]kyber.Point, n)
	// (2) Share decryption (trustees)
	for i := 0; i < n; i++ {
		sH[i] = pubPoly.Eval(encShares[i].S.I).V
	}
	logrus.Info("end distribution and start decryption2")
	for i := 0; i < n; i++ {
		pvss.VerifyEncShare(suite, H, X[i], sH[i], encShares[i])
	}
	logrus.Info("end decryption")
}

func TestBIVSSBench(tt *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	secret := suite.Scalar().SetInt64(123)

	t := 10
	u := t
	n := 20

	x := make([]kyber.Scalar, n) // trustee private keys
	X := make([]kyber.Point, n)  // trustee public keys
	poly := GetSamplePoly(suite, secret)

	for i := 0; i < n; i++ {
		x[i] = suite.Scalar().Pick(suite.RandomStream())
		X[i] = suite.Point().Mul(x[i], nil)
	}
	serverPoints := make([][]BiPoint, n)
	encShares := make([][]kyber.Point,n)

	logrus.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.StampMicro,
	})
	logrus.Info("start distribution")
	for i := 0; i < n; i++ {
		serverPoints[i] = make([]BiPoint, u)
		encShares[i] = make([]kyber.Point, u)
		for j := 0; j < u; j++ {
			serverPoints[i][j] = poly.Eval(int64(i+1),int64(j))
			encShares[i][j] = suite.Point().Mul(serverPoints[i][j].V,X[i])
		}
	}
	H := suite.Point().Pick(suite.XOF([]byte("H")))
	commit := poly.Commit(H)
	w := suite.Scalar().SetInt64(int64(300))
	c := suite.Scalar().SetInt64(int64(2))
	logrus.Info("end distribution and start decryption")
	//distribute end
	for i := 0; i < n; i++ {
		for j :=0; j<u;j++{
			r := GenerateRScalar(suite, w, c,serverPoints[i][j])
			VerifyRScalar(suite, w, c, r, i+1,j, X[i], commit, encShares[i][j])
		}
	}
	logrus.Info("end decryption ")

}


func TestOPTBIVSSBench(tt *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	secret := suite.Scalar().SetInt64(123)

	t := 10
	u := t
	n := 20

	x := make([]kyber.Scalar, n) // trustee private keys
	X := make([]kyber.Point, n)  // trustee public keys
	poly := GetSamplePoly(suite, secret)

	for i := 0; i < n; i++ {
		x[i] = suite.Scalar().Pick(suite.RandomStream())
		X[i] = suite.Point().Mul(x[i], nil)
	}
	serverPoints := make([][]BiPoint, n)
	encShares := make([][]kyber.Point,n)

	logrus.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.StampMicro,
	})
	logrus.Info("start distribution")
	for i := 0; i < n; i++ {
		serverPoints[i] = make([]BiPoint, u)
		encShares[i] = make([]kyber.Point, u)
		for j := 0; j < u; j++ {
			serverPoints[i][j] = poly.Eval(int64(i+1),int64(j))
			encShares[i][j] = suite.Point().Mul(serverPoints[i][j].V,X[i])
		}
	}
	H := suite.Point().Pick(suite.XOF([]byte("H")))
	commit := poly.OptCommit(H,n)
	logrus.Info("end distribution and start decryption")
	w := suite.Scalar().SetInt64(int64(300))
	c := suite.Scalar().SetInt64(int64(2))
	//distribute end
	for i := 0; i < n; i++ {
		r := GenerateRScalar(suite, w, c,serverPoints[i][1])
		VerifyOptRScalar(suite, w, c, r, i+1,1, X[i], commit, encShares[i][1])
	}
	logrus.Info("end decryption ")

}