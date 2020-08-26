package bivss

import (
	"dkms/share"

	"github.com/sirupsen/logrus"
	"go.dedis.ch/kyber/v3"
)

// Suite describes the functionalities needed by this package in order to
// function correctly.
type Suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.Encoding
	kyber.XOFFactory
	kyber.Random
}
type EncryptedData struct {
	x              int
	y              int
	encryptedPoint kyber.Point
	committedPoint kyber.Point
}

type NodeData struct {
	nodeIdx    int
	secretData share.YPoly
}

type RecoveryData struct {
	fromNodeIdx    int
	failureNodeIdx int
	recoveryPoint  share.BiPoint
}

func MakeEncryptShares(suite Suite, CommitBasePoint kyber.Point, publicKeys []kyber.Point, secret kyber.Scalar, t int, u int) (*share.BiPoly, [][]*EncryptedData, error) {
	n := len(publicKeys)
	encData := make([][]*EncryptedData, n)
	for i := range encData {
		encData[i] = make([]*EncryptedData, t)
	}

	priPoly, err := share.NewBiPoly(suite, t, u, secret, suite.RandomStream())
	if err != nil {
		return nil, nil, err
	}

	logrus.Info("private polynomial created")

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

func MakeRecoveryData(failIndex int) {

}
