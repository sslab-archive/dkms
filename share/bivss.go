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

func MakeEncryptShares(suite Suite, CommitBasePoint kyber.Point, publicKeys []kyber.Point, secret kyber.Scalar, t int, u int) (*BiPoly, [][]*EncryptedData, error) {
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

func Recover([]*RecoveryData) (*node.Node, error) {
	panic("impl me!")
}
