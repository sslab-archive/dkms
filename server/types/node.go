package types

import (
	"dkms/node"
	"dkms/share"

	"go.dedis.ch/kyber/v3"
)

type Node struct {
	Address         Address
	PublicKeyHex    string
	CommitBaseHex   string
	CommitPointsHex []string
}

func (n *Node) ToDomain(suite share.Suite) (*node.Node, error) {
	commitBase, err := share.HexToPoint(n.CommitBaseHex, suite)
	if err != nil {
		return nil, err
	}

	pubKey, err := share.HexToPoint(n.PublicKeyHex, suite)
	if err != nil {
		return nil, err
	}

	domainNode := node.NewNode(n.Address.Ip+n.Address.Port, n.Address, commitBase)

	commitPoints := make([]kyber.Point, 0)
	for _, oneCommitPoint := range n.CommitPointsHex {
		p, err := share.HexToPoint(oneCommitPoint, suite)
		if err != nil {
			return nil, err
		}
		commitPoints = append(commitPoints, p)
	}
	domainNode.PubKey = pubKey
	domainNode.CommitPoints = commitPoints
	return domainNode, nil
}
