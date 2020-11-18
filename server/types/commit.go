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
	KCommitsHex        []string `json:"kCommitsHex"`
}

func NewPolyCommitData(from share.CommitData) (*PolyCommitData, error) {
	commitBasePointBin, err := from.H.MarshalBinary()
	if err != nil {
		return nil, err
	}

	secretCommitBin, err := from.SecretCommit.MarshalBinary()
	if err != nil {
		return nil, err
	}

	xCommitHex := make([]string, 0)
	for _, oneXCommit := range from.XCommits {
		b, err := oneXCommit.MarshalBinary()
		if err != nil {
			return nil, err
		}
		xCommitHex = append(xCommitHex, hex.EncodeToString(b))
	}

	yCommitHex := make([]string, 0)
	for _, oneYCommit := range from.YCommits {
		b, err := oneYCommit.MarshalBinary()
		if err != nil {
			return nil, err
		}
		yCommitHex = append(yCommitHex, hex.EncodeToString(b))
	}

	kCommitHex := make([]string, 0)
	for _, oneKCommit := range from.KCommits {
		b, err := oneKCommit.MarshalBinary()
		if err != nil {
			return nil, err
		}
		kCommitHex = append(kCommitHex, hex.EncodeToString(b))
	}

	return &PolyCommitData{
		CommitBasePointHex: hex.EncodeToString(commitBasePointBin),
		SecretCommitHex:    hex.EncodeToString(secretCommitBin),
		XCommitsHex:        xCommitHex,
		YCommitsHex:        yCommitHex,
		KCommitsHex:        kCommitHex,
	}, nil

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

	kCommits := make([]kyber.Point, 0)
	for _, oneKCommitsHex := range pcd.KCommitsHex {
		oneKCommitsBin, err := hex.DecodeString(oneKCommitsHex)
		if err != nil {
			return nil, err
		}
		p := suite.Point()
		err = p.UnmarshalBinary(oneKCommitsBin)
		if err != nil {
			return nil, err
		}

		kCommits = append(kCommits, p)
	}

	return &share.CommitData{
		G:            suite,
		H:            commitBasePoint,
		SecretCommit: secretCommit,
		XCommits:     xCommits,
		YCommits:     yCommits,
		KCommits:     kCommits,
	}, nil
}
