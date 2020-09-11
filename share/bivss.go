package share

import (
	"encoding/hex"
	"fmt"

	"dkms/node"

	"github.com/sirupsen/logrus"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
)

type EncryptedData struct {
	x              int64
	y              int64
	encryptedPoint kyber.Point
	committedPoint kyber.Point
}

type RecoveryData struct {
	FromNodeIdx    int64
	FailureNodeIdx int64
	RecoveryPoint  BiPoint
	CommitData     CommitData
}

func MakeEncryptShares(suite node.Suite, CommitBasePoint kyber.Point, publicKeys []kyber.Point, secret kyber.Scalar, t int, u int) (*BiPoly, [][]*EncryptedData, error) {
	n := len(publicKeys)
	encData := make([][]*EncryptedData, n)
	for i := range encData {
		encData[i] = make([]*EncryptedData, t)
	}

	priPoly, err := NewBiPoly(suite, t, u, secret, suite.RandomStream())
	if err != nil {
		return nil, nil, err
	}

	logrus.Info(fmt.Sprintf("private polynomial created, t : %d, u : %d", priPoly.T(), priPoly.U()))

	for i := range encData {
		yPoly := priPoly.GetYPoly(int64(i))
		for j := range encData[i] {
			point := yPoly.Eval(int64(j))

			encData[i][j] = &EncryptedData{
				x:              int64(i),
				y:              int64(j),
				encryptedPoint: suite.Point().Mul(point.V, publicKeys[i]),
				committedPoint: suite.Point().Mul(point.V, CommitBasePoint),
			}

		}
	}

	return priPoly, encData, nil
}

func PointToHex(p kyber.Point) (string, error) {
	b, err := p.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func HexToPoint(hexString string, g kyber.Group) (kyber.Point, error) {
	b, err := hex.DecodeString(hexString)

	if err != nil {
		return nil, err
	}
	p := g.Point()
	err = p.UnmarshalBinary(b)

	if err != nil {
		return nil, err
	}
	return p, nil
}

func ScalarToHex(p kyber.Scalar) (string, error) {
	b, err := p.MarshalBinary()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func HexToScalar(hexString string, g kyber.Group) (kyber.Scalar, error) {
	b, err := hex.DecodeString(hexString)

	if err != nil {
		return nil, err
	}
	s := g.Scalar()
	err = s.UnmarshalBinary(b)

	if err != nil {
		return nil, err
	}
	return s, nil
}

func GenerateWScalar(g kyber.Group) kyber.Scalar {
	return g.Scalar().Pick(random.New())
}

func GenerateCScalar(g kyber.Group) kyber.Scalar {
	return g.Scalar().Pick(random.New())
}

func GenerateRScalar(g kyber.Group, w kyber.Scalar, c kyber.Scalar, point BiPoint) kyber.Scalar {
	pc := g.Scalar().Mul(point.V, c)
	r := g.Scalar()
	r = r.Sub(r, pc)
	return r
}

func VerifyRScalar(g kyber.Group, w kyber.Scalar, c kyber.Scalar, r kyber.Scalar, x int, y int, publicKey kyber.Point, commitData CommitData, encryptedPoint kyber.Point) {

}

func verifyCommitPhase(g kyber.Group, w kyber.Scalar, c kyber.Scalar, r kyber.Scalar, x int, y int, commitData CommitData) bool {

	xV := g.Point().Null()
	xI := g.Scalar().SetInt64(int64(x))
	finV := g.Point().Null()
	for i := len(commitData.XCommits) - 1; i >= 0; i-- {
		xV.Mul(xI, xV)
		xV.Add(xV, commitData.XCommits[i])
	}
	xV.Mul(xI, xV)

	yV := g.Point().Null()
	yI := g.Scalar().SetInt64(int64(y))
	for i := len(commitData.YCommits) - 1; i >= 0; i-- {
		yV.Mul(yI, yV)
		yV.Add(yV, commitData.YCommits[i])
	}
	yV.Mul(yI, yV)

	finV.Add(finV, commitData.SecretCommit)
	finV.Add(finV, xV)
	finV.Add(finV, yV)

	finV.Mul(c, finV)
	finV.Mul(r, finV)

	committedW := g.Point().Mul(w, commitData.H)
	return finV.Equal(committedW)
}

func verifyPublicPhase(g kyber.Group, w kyber.Scalar, c kyber.Scalar, r kyber.Scalar, x int, y int, publicKey kyber.Point, encryptedPoint kyber.Point) bool {
	panic("impl me!")
}

func Recover([]*RecoveryData) (*node.Node, error) {
	panic("impl me!")
}
