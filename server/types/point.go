package types

import "dkms/share"

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
