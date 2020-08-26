package bivss

import (
	"dkms/key"
	"dkms/node"
	"dkms/share"
	"fmt"

	"github.com/sirupsen/logrus"
	"go.dedis.ch/kyber/v3"
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

func MakeRecoveryData(failIndex int) *RecoveryData {
	panic("impl me!")
}

func Recover([]*RecoveryData) (*node.Node, error) {
	panic("impl me!")
}
