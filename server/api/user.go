/*
 * Copyright 2019 hea9549
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package api

import (
	"errors"
	"fmt"
	"net/http"

	"dkms/checker"
	"dkms/node"
	"dkms/server/interfaces"
	"dkms/server/types"
	"dkms/share"
	"dkms/user"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type User struct {
	repository           user.Repository
	nodeService          *node.Service
	checkerLogRepository checker.LogRepository
}

func NewUser(repository user.Repository, checkerLogRepository checker.LogRepository, nodeService *node.Service) *User {
	return &User{
		repository:           repository,
		checkerLogRepository: checkerLogRepository,
		nodeService:          nodeService,
	}
}

func (u *User) RegisterUser(c *gin.Context) {
	var requestBody interfaces.KeyRegisterRequest
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		BadRequestError(c, errors.New("failed to bind key register request body"))
		return
	}

	commit, err := requestBody.CommitData.ToDomain(u.nodeService.Suite)
	if err != nil {
		InternalServerError(c, err)
		return
	}

	points, err := types.EncryptedMessageToPoints(requestBody.EncryptedData, u.nodeService.GetMyPrivateKey(), u.nodeService.Suite)
	if err != nil {
		InternalServerError(c, err)
		return
	}

	yPoly, err := share.LagrangeForYPoly(u.nodeService.Suite, points[:requestBody.U], requestBody.U)
	if err != nil {
		InternalServerError(c, err)
		return
	}

	xPoly, err := share.LagrangeForXPoly(u.nodeService.Suite, points[requestBody.U:], requestBody.T)
	if err != nil {
		InternalServerError(c, err)
		return
	}

	nodes := make([]*node.Node, 0)
	for _, oneNode := range requestBody.Nodes {
		n, err := oneNode.ToDomain(u.nodeService.Suite)
		if err != nil {
			InternalServerError(c, err)
			return
		}

		nodes = append(nodes, n)
	}

	registerUser := user.User{
		Id:         requestBody.UserId,
		PolyCommit: *commit,
		MyYPoly:    *yPoly,
		MyXPoly:    *xPoly,
		Nodes:      nodes,
	}

	err = u.repository.Save(&registerUser)
	if err != nil {
		InternalServerError(c, err)
		return
	}
	logrus.Info(fmt.Sprintf("------------User Registerd Information------------"))
	logrus.Info(fmt.Sprintf("id : %s, t:%d, u:%d is registered. my index : %d", registerUser.Id, requestBody.T, requestBody.U, xPoly.Y))
	logrus.Info(fmt.Sprintf("nodes size : %d", len(nodes)))
	logrus.Info(fmt.Sprintf("------------Registered Nodes Information------------"))
	logrus.Info(fmt.Sprintf("%5s|%15s|%8s|%5s|", "Index", "Address", "encPtLen", "pub"))
	for _, oneNode := range nodes {
		logrus.Info(fmt.Sprintf("%5d|%15s|%8d|%5s|", oneNode.Index, oneNode.Address.Address(), len(oneNode.EncryptedPoints), oneNode.PubKey.String()[:5]))
	}
	c.JSON(http.StatusOK, interfaces.KeyRegisterResponse{
		UserId: registerUser.Id,
		T:      xPoly.T(),
		U:      yPoly.U(),
		Commit: requestBody.CommitData,
		Nodes:  requestBody.Nodes,
	})
}

func (u *User) UserInformation(c *gin.Context) {
	var pathParams struct {
		Id string `uri:"id" binding:"required"`
	}

	if err := c.ShouldBindUri(&pathParams); err != nil {
		BadRequestError(c, errors.New("path variable :id does not exists"))
		return
	}
	us, err := u.repository.Get(pathParams.Id)
	if err != nil {
		InternalServerError(c, err)
		return
	}
	nodes := make([]types.Node, 0)
	for _, oneNode := range us.Nodes {
		typeNode, err := types.NewNode(*oneNode)
		if err != nil {
			InternalServerError(c, err)
			return
		}
		nodes = append(nodes, *typeNode)
	}
	commit, err := types.NewPolyCommitData(us.PolyCommit)
	if err != nil {
		InternalServerError(c, err)
		return
	}
	logs := u.checkerLogRepository.GetLogsByUserId(us.Id)[:50]
	c.JSON(http.StatusOK, interfaces.GetUserInformationResponse{
		Id:           us.Id,
		CommitData:   *commit,
		IsMonitoring: us.Monitoring,
		T:            us.MyXPoly.T(),
		U:            us.MyYPoly.U(),
		Nodes:        nodes,
		Logs:         logs,
	})
	return
}
