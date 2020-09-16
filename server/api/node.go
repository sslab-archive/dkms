package api

import (
	"net/http"

	"dkms/node"
	"dkms/server/interfaces"
	"dkms/share"

	"github.com/gin-gonic/gin"
)

type Node struct {
	service *node.Service
}

func NewNode(nodeService *node.Service) *Node {
	return &Node{
		service: nodeService,
	}
}

func (n *Node) ServerInfo(c *gin.Context) {
	h, err := share.PointToHex(n.service.GetMyPublicKey())
	if err != nil {
		InternalServerError(c, err)
		return
	}

	res := interfaces.GetServerInfo{
		Ip:        n.service.GetMyAddress().Ip,
		Port:      n.service.GetMyAddress().Port,
		PubKeyHex: h,
	}
	c.JSON(http.StatusOK, res)
	return
}
