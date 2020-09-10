package share

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

func TestLagrangeForYPoly(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	secret := suite.Scalar().SetInt64(int64(10))

	xCoeffs := make([]kyber.Scalar, 2)
	xCoeffs[0] = suite.Scalar().SetInt64(int64(2))
	xCoeffs[1] = suite.Scalar().SetInt64(int64(3))

	yCoeffs := make([]kyber.Scalar, 2)
	yCoeffs[0] = suite.Scalar().SetInt64(int64(4))
	yCoeffs[1] = suite.Scalar().SetInt64(int64(5))

	poly := BiPoly{
		g:       suite,
		secret:  secret,
		xCoeffs: xCoeffs,
		yCoeffs: yCoeffs,
	} // t = u = 3

	//y1 := poly.GetYPoly(1) // const 15
	//x1 := poly.GetXPoly(1) // const 19
	p1_2 := poly.Eval(1, 2)
	p1_3 := poly.Eval(1, 3)
	p1_4 := poly.Eval(1, 4)

	points := make([]BiPoint, 3)
	points[0] = p1_2
	points[1] = p1_3
	points[2] = p1_4

	recoveredPoly, err := LagrangeForYPoly(suite, points, poly.U())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println(poly.U())
	fmt.Println(recoveredPoly.U())
	recoverConstant, err := ScalarToInt(recoveredPoly.constant)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(recoverConstant)
}

func TestTwo(t *testing.T) {
	curve := btcec.S256()
	secret := big.NewInt(123456789)
	prvKey := big.NewInt(299872984179287342)

	pubX, pubY := curve.ScalarBaseMult(prvKey.Bytes())
	baseX, baseY := curve.ScalarBaseMult(secret.Bytes())

	encryptedX, encryptedY := curve.ScalarMult(pubX, pubY, secret.Bytes())

	inv := big.NewInt(0).ModInverse(prvKey, curve.N)
	recoveredX, recoveredY := curve.ScalarMult(encryptedX, encryptedY, inv.Bytes())
	fmt.Println(recoveredX, recoveredY)
	fmt.Println(baseX, baseY)

}

func TestThree(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	two := suite.Point().Mul(suite.Scalar().SetInt64(2), nil)
	three := suite.Point().Mul(suite.Scalar().SetInt64(3), nil)

	two_p_three := suite.Point().Add(two, three)
	rec_two := suite.Point().Sub(two_p_three,three)

	fmt.Println(two.String())
	fmt.Println(rec_two.String())
}
