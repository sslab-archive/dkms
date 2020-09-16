package types

import (
	"dkms/node"
	"dkms/share"

	"go.dedis.ch/kyber/v3"
)

type Node struct {
	Address            Address
	PublicKeyHex       string
	Index              int
	EncryptedPointsHex []string
}

func (n *Node) ToDomain(suite share.Suite) (*node.Node, error) {

	pubKey, err := share.HexToPoint(n.PublicKeyHex, suite)
	if err != nil {
		return nil, err
	}

	encryptedPoints := make([]kyber.Point, 0)
	for _, oneEncryptedPoints := range n.EncryptedPointsHex {
		p, err := share.HexToPoint(oneEncryptedPoints, suite)
		if err != nil {
			return nil, err
		}
		encryptedPoints = append(encryptedPoints, p)
	}
	domainNode := node.NewNode(n.Address.Ip+n.Address.Port, n.Index, n.Address)
	domainNode.PubKey = pubKey
	domainNode.EncryptedPoints = encryptedPoints
	return domainNode, nil
}

func NewNode(from node.Node) (*Node, error) {
	h, err := share.PointToHex(from.PubKey)
	if err != nil {
		return nil, err
	}
	encPointsHex := make([]string, 0)
	for _, onePoint := range from.EncryptedPoints {
		h, err := share.PointToHex(onePoint)
		if err != nil {
			return nil, err
		}
		encPointsHex = append(encPointsHex, h)
	}
	return &Node{
		Address:            from.Address,
		PublicKeyHex:       h,
		Index:              from.Index,
		EncryptedPointsHex: encPointsHex,
	}, nil
}
