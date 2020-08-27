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
	"dkms/interfaces"
	"dkms/server"
	"dkms/share"
	"dkms/share/bivss"
	"dkms/user"
	"errors"
	"github.com/gin-gonic/gin"
	"go.dedis.ch/kyber/v3"
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

	commit := share.CommitData{}
	if err := commit.UnMarshal(requestBody.CommitData); err != nil {
		server.InternalServerError(c, err)
		return
	}

	points := make([]kyber.Point, 0)
	for _, pointHex := range requestBody.EncryptedPointsHex {
		point, err := share.HexToPoint(pointHex,u.shareService.Suite)
		if err!=nil{
			server.InternalServerError(c, err)
			return
		}
		points = append(points, point)
	}
	u.shareService.
	//userIda := user.User{
	//	Id:         requestBody.UserId,
	//	PolyCommit: commit,
	//	MyYPoly:    share.YPoly{},
	//	Nodes:      nil,
	//}
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
