package types

import (
	"encoding/hex"
	"encoding/json"

	"dkms/share"

	"go.dedis.ch/kyber/v3"
)

type BiPoint struct {
	X         int64
	Y         int64
	ScalarHex string
}

func NewBiPoint(from share.BiPoint) (*BiPoint, error) {
	sh, err := share.ScalarToHex(from.V)
	if err != nil {
		return nil, err
	}
	return &BiPoint{
		X:         from.X,
		Y:         from.Y,
		ScalarHex: sh,
	}, nil
}

func (bp *BiPoint) ToDomain(suite share.Suite) (*share.BiPoint, error) {
	s, err := share.HexToScalar(bp.ScalarHex, suite)
	if err != nil {
		return nil, err
	}
	return &share.BiPoint{
		X: bp.X,
		Y: bp.Y,
		V: s,
	}, err
}

func EncryptedMessageToPoints(encMessage share.EncryptedMessage, prvKey kyber.Scalar, suite share.Suite) ([]share.BiPoint, error) {
	msg, err := share.Decrypt(suite, prvKey, encMessage)
	typePoints := make([]BiPoint, 0)
	err = json.Unmarshal(msg, &typePoints)

	points := make([]share.BiPoint, 0)

	for _, oneTypePoints := range typePoints {
		pointBytes, err := hex.DecodeString(oneTypePoints.ScalarHex)
		if err != nil {
			return nil, err
		}
		p := suite.Scalar()
		err = p.UnmarshalBinary(pointBytes)
		if err != nil {
			return nil, err
		}

		points = append(points, share.BiPoint{
			X: oneTypePoints.X,
			Y: oneTypePoints.Y,
			V: p,
		})
	}

	if err != nil {
		return nil, err
	}

	return points, nil
}

func PointsToEncryptedMessage(points []share.BiPoint, pubKey kyber.Point, suite share.Suite) (*share.EncryptedMessage, error) {
	typePoints := make([]BiPoint, 0)
	for _, onePoint := range points {
		b, err := onePoint.V.MarshalBinary()
		if err != nil {
			return nil, err
		}
		tp := BiPoint{
			X:         onePoint.X,
			Y:         onePoint.Y,
			ScalarHex: hex.EncodeToString(b),
		}
		typePoints = append(typePoints, tp)
	}
	pointsStr, err := json.Marshal(typePoints)
	if err != nil {
		return nil, err
	}
	encryptedMsg, err := share.Encrypt(suite, pubKey, pointsStr)
	if err != nil {
		return nil, err
	}

	return encryptedMsg, nil
}
