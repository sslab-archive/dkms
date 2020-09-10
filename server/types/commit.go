package types

import (
	"encoding/hex"

	"dkms/share"

	"go.dedis.ch/kyber/v3"
)

type PolyCommitData struct {
	CommitBasePointHex string   `json:"commitBasePointHex"`
	SecretCommitHex    string   `json:"secretCommitHex"`
	XCommitsHex        []string `json:"xCommitsHex"`
	YCommitsHex        []string `json:"yCommitsHex"`
}

func NewPolyCommitData(from share.CommitData) (*PolyCommitData, error) {
	panic("impl me!")
	//
	//return &PolyCommitData{
	//	CommitBasePointHex: "",
	//	SecretCommitHex:    "",
	//	XCommitsHex:        nil,
	//	YCommitsHex:        nil,
	//}, nil

}

func (pcd *PolyCommitData) ToDomain(suite share.Suite) (*share.CommitData, error) {
	commitBasePointBin, err := hex.DecodeString(pcd.CommitBasePointHex)
	if err != nil {
		return nil, err
	}
	commitBasePoint := suite.Point()
	err = commitBasePoint.UnmarshalBinary(commitBasePointBin)
	if err != nil {
		return nil, err
	}

	secretCommitBin, err := hex.DecodeString(pcd.SecretCommitHex)
	if err != nil {
		return nil, err
	}
	secretCommit := suite.Point()
	err = secretCommit.UnmarshalBinary(secretCommitBin)
	if err != nil {
		return nil, err
	}

	xCommits := make([]kyber.Point, 0)
	for _, oneXCommitsHex := range pcd.XCommitsHex {
		oneXCommitsBin, err := hex.DecodeString(oneXCommitsHex)
		if err != nil {
			return nil, err
		}
		p := suite.Point()
		err = p.UnmarshalBinary(oneXCommitsBin)
		if err != nil {
			return nil, err
		}

		xCommits = append(xCommits, p)
	}

	yCommits := make([]kyber.Point, 0)
	for _, oneYCommitsHex := range pcd.YCommitsHex {
		oneYCommitsBin, err := hex.DecodeString(oneYCommitsHex)
		if err != nil {
			return nil, err
		}
		p := suite.Point()
		err = p.UnmarshalBinary(oneYCommitsBin)
		if err != nil {
			return nil, err
		}

		yCommits = append(yCommits, p)
	}

	return &share.CommitData{
		G:            suite,
		H:            commitBasePoint,
		SecretCommit: secretCommit,
		XCommits:     xCommits,
		YCommits:     yCommits,
	}, nil
}
