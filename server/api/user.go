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
	"encoding/hex"
	"errors"

	"dkms/node"
	"dkms/server"
	"dkms/server/interfaces"
	"dkms/server/types"
	"dkms/share"
	"dkms/user"

	"github.com/gin-gonic/gin"
)

type User struct {
	repository   user.Repository
	shareService share.Service
}

func NewUser(repository user.Repository, shareService share.Service) *User {
	return &User{
		repository:   repository,
		shareService: shareService,
	}
}

func (u *User) RegisterUser(c *gin.Context) {
	var requestBody interfaces.KeyRegisterRequest
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		server.BadRequestError(c, errors.New("failed to bind key register request body"))
		return
	}

	commit := share.NewCommitData(u.shareService.Suite)
	if err := commit.UnMarshal(requestBody.CommitData); err != nil {
		server.InternalServerError(c, err)
		return
	}

	points, err := u.shareService.EncryptedMessageToPoints(requestBody.EncryptedData)
	if err != nil {
		server.InternalServerError(c, err)
		return
	}

	yPoly, err := share.LagrangeForYPoly(u.shareService.Suite, points[:requestBody.U], requestBody.U)
	if err != nil {
		server.InternalServerError(c, err)
		return
	}

	xPoly, err := share.LagrangeForXPoly(u.shareService.Suite, points[requestBody.U:], requestBody.T)
	if err != nil {
		server.InternalServerError(c, err)
		return
	}

	err = commit.UnMarshal(requestBody.CommitData)
	if err != nil {
		server.InternalServerError(c, err)
		return
	}

	nodes := make([]node.Node, 0)
	for _, oneNode := range requestBody.Nodes {
		n, err := oneNode.ToDomain(u.shareService.Suite)
		if err != nil {
			server.InternalServerError(c, err)
			return
		}

		nodes = append(nodes, *n)
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
		server.InternalServerError(c, err)
		return
	}
}

func (u *User) StartVerify(c *gin.Context) {
	var requestBody interfaces.StartVerifyRequest
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		server.BadRequestError(c, errors.New("failed to bind start verify request body"))
		return
	}
	var pathParams struct {
		ID string `uri:"id" binding:"required"`
	}
	if err := c.ShouldBindUri(&pathParams); err != nil {
		server.BadRequestError(c, errors.New("path variable :id does not exists"))
		return
	}

}

func (u *User) VerifyChallenge(c *gin.Context) {
	var requestBody interfaces.VerifyChallengeRequest
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		server.BadRequestError(c, errors.New("failed to bind verify challenge request body"))
		return
	}
	var pathParams struct {
		ID string `uri:"id" binding:"required"`
	}
	if err := c.ShouldBindUri(&pathParams); err != nil {
		server.BadRequestError(c, errors.New("path variable :id does not exists"))
		return
	}
}

func pointToTypes(bp share.BiPoint) (*types.BiPoint, error) {
	b, err := bp.V.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &types.BiPoint{
		X:         bp.X,
		Y:         bp.Y,
		ScalarHex: hex.EncodeToString(b),
	}, nil
}

func pointFromTypes(bp *types.BiPoint) (share.BiPoint, error) {
	panic("impl me!")
}
