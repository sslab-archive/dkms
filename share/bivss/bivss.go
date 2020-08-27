package bivss

import (
	"encoding/hex"
	"fmt"

	"dkms/key"
	"dkms/node"
	"dkms/share"

	"github.com/sirupsen/logrus"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
)

type EncryptedData struct {
	x              int
	y              int
	encryptedPoint kyber.Point
	committedPoint kyber.Point
}

type RecoveryData struct {
	fromNodeIdx    int
	failureNodeIdx int
	recoveryPoint  share.BiPoint
}

func MakeEncryptShares(suite key.Suite, CommitBasePoint kyber.Point, publicKeys []kyber.Point, secret kyber.Scalar, t int, u int) (*share.BiPoly, [][]*EncryptedData, error) {
	n := len(publicKeys)
	encData := make([][]*EncryptedData, n)
	for i := range encData {
		encData[i] = make([]*EncryptedData, t)
	}

	priPoly, err := share.NewBiPoly(suite, t, u, secret, suite.RandomStream())
	if err != nil {
		return nil, nil, err
	}

	logrus.Info(fmt.Sprintf("private polynomial created, t : %d, u : %d", priPoly.T(), priPoly.U()))

	for i := range encData {
		yPoly := priPoly.GetYPoly(i)
		for j := range encData[i] {
			point := yPoly.Eval(j)

			encData[i][j] = &EncryptedData{
				x:              i,
				y:              j,
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

func GenerateWScalar(g kyber.Group) kyber.Scalar {
	ret
	g.Scalar().Pick(random.New())
}

func MakeRecoveryData(failIndex int) *RecoveryData {
	panic("impl me!")
}

func Recover([]*RecoveryData) (*node.Node, error) {
	panic("impl me!")
}
