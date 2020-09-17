package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"dkms/node"
	"dkms/server/interfaces"
	"dkms/server/types"
	"dkms/share"

	"go.dedis.ch/kyber/v3"
)

type Client struct {
	userId     string
	suite      share.Suite
	privateKey kyber.Scalar
}

func NewClient(id string, suite share.Suite, prvKeyHex string) (*Client, error) {
	p, err := share.HexToScalar(prvKeyHex, suite)
	if err != nil {
		return nil, err
	}
	return &Client{
		userId:     id,
		suite:      suite,
		privateKey: p,
	}, nil
}

func (c *Client) RegisterKey(serverAddresses []types.Address, t int, u int) error {
	poly, err := share.NewBiPoly(c.suite, t, u, c.privateKey, c.suite.RandomStream())
	if err != nil {
		return err
	}

	nodes := make([]node.Node, 0)
	for idx, oneServerAddr := range serverAddresses {
		url := "http://" + oneServerAddr.Address() + "/info"
		resp, err := http.Get(url)
		if err != nil {
			return err
		}

		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}

		r := interfaces.GetServerInfo{}
		err = json.Unmarshal(b, &r)
		if err != nil {
			return err
		}

		n := node.NewNode(idx+1, oneServerAddr)

		p, err := share.HexToPoint(r.PubKeyHex, c.suite)
		if err != nil {
			return err
		}

		n.PubKey = p
		nodes = append(nodes, *n)
	}

	// prepare data for register user
	encMsgRequest := make([]*share.EncryptedMessage, 0)
	typeNodes := make([]types.Node, 0)
	commit := poly.Commit(c.suite.Point().Pick(c.suite.XOF([]byte("H"))))
	typeCommit, err := types.NewPolyCommitData(commit)
	if err != nil {
		return nil
	}
	for _, oneNode := range nodes {
		rawPoints := make([]share.BiPoint, 0)
		encPoints := make([]kyber.Point, 0)
		yPoly := poly.GetYPoly(int64(oneNode.Index))
		xPoly := poly.GetXPoly(int64(oneNode.Index))
		for i := 1; i <= yPoly.U(); i++ {
			yp := yPoly.Eval(int64(i))
			rawPoints = append(rawPoints, yp)
			encPoints = append(encPoints, c.suite.Point().Mul(yp.V, oneNode.PubKey))
		}

		for i := 1; i <= xPoly.T(); i++ {
			xp := xPoly.Eval(int64(i))
			rawPoints = append(rawPoints, xp)
			encPoints = append(encPoints, c.suite.Point().Mul(xp.V, oneNode.PubKey))
		}
		encMsg, err := types.PointsToEncryptedMessage(rawPoints, oneNode.PubKey, c.suite)
		if err != nil {
			return err
		}

		oneNode.EncryptedPoints = encPoints
		encMsgRequest = append(encMsgRequest, encMsg)
		if n, err := types.NewNode(oneNode); err == nil {
			typeNodes = append(typeNodes, *n)
		} else {
			return err
		}
	}

	// register user data to each server
	for idx, oneNode := range nodes {
		url := "http://" + oneNode.Address.Address() + "/user"
		reqBody := interfaces.KeyRegisterRequest{
			UserId:        c.userId,
			EncryptedData: *encMsgRequest[idx],
			Nodes:         typeNodes,
			CommitData:    *typeCommit,
			T:             t,
			U:             u,
		}
		b, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		resp, err := http.Post(url, "application/json", bytes.NewReader(b))
		fmt.Println(resp)
	}
	return nil
}
