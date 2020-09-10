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

func (pcd *PolyCommitData) ToDomain(suite share.Suite) (*share.CommitData, error) {
	commitBasePointBin, err := hex.DecodeString(pcd.CommitBasePointHex)
	if err != nil {
		return nil, err
	}

	secretCommitBin, err := hex.DecodeString(pcd.SecretCommitHex)
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

	h := suite.Point()
	err = h.UnmarshalBinary(commitBasePointBin)
	if err != nil {
		return nil, err
	}

	secretCommit := suite.Point()
	secretCommit.UnmarshalBinary()
	return &share.CommitData{
		G:            suite,
		H:            h,
		SecretCommit: nil,
		XCommits:     nil,
		YCommits:     nil,
	}, nil
}
