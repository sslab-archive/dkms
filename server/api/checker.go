package api

import (
	"errors"
	"net/http"

	"dkms/checker"
	"dkms/node"
	"dkms/server/interfaces"
	"dkms/share"
	"dkms/user"

	"github.com/gin-gonic/gin"
)

type Checker struct {
	userRepository user.Repository
	nodeService    node.Service
	checkerService checker.Service
}

func (ch *Checker) AddCheckUser(c *gin.Context) {
	var requestBody interfaces.AddCheckUserRequest
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		BadRequestError(c, errors.New("failed to bind start verify request body"))
		return
	}

	u, err := ch.userRepository.Get(requestBody.UserId)
	if err != nil {
		BadRequestError(c, errors.New("body variable user does not exists"))
		return
	}

	err = ch.checkerService.AddCheckUser(u)
	if err != nil {
		BadRequestError(c, err)
		return
	}

	c.JSON(http.StatusOK, interfaces.AddCheckUserResponse{
		UserId: u.Id,
		Msg:    "success",
	})
	return
}

func (ch *Checker) RemoveCheckUser(c *gin.Context) {
	var requestBody interfaces.RemoveCheckUserRequest
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		BadRequestError(c, errors.New("failed to bind start verify request body"))
		return
	}

	err := ch.checkerService.RemoveCheckUser(requestBody.UserId)
	if err != nil {
		BadRequestError(c, err)
		return
	}

	c.JSON(http.StatusNoContent, interfaces.RemoveCheckUserResponse{
		UserId: requestBody.UserId,
		Msg:    "success",
	})
}

func (ch *Checker) StartVerify(c *gin.Context) {
	var requestBody interfaces.StartVerifyRequest
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		BadRequestError(c, errors.New("failed to bind start verify request body"))
		return
	}

	u, err := ch.userRepository.Get(requestBody.UserId)
	if err != nil {
		BadRequestError(c, err)
		return
	}

	if u.Monitoring == false {
		BadRequestError(c, errors.New("user is not in monitor status"))
		return
	}

	w := share.GenerateWScalar(ch.nodeService.Suite)
	hexStr, err := share.ScalarToHex(w)
	if err != nil {
		InternalServerError(c, err)
		return
	}

	c.JSON(http.StatusOK, interfaces.StartVerifyResponse{
		UserId:     u.Id,
		WScalarHex: hexStr,
	})
}

func (ch *Checker) VerifyChallenge(c *gin.Context) {
	var requestBody interfaces.VerifyChallengeRequest
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		BadRequestError(c, errors.New("failed to bind verify challenge request body"))
		return
	}

	u, err := ch.userRepository.Get(requestBody.UserId)
	if err != nil {
		BadRequestError(c, err)
		return
	}

	if u.Monitoring == false {
		BadRequestError(c, errors.New("user is not in monitor status"))
		return
	}

	wScalar, err := share.HexToScalar(requestBody.WScalarHex, ch.nodeService.Suite)
	if err != nil {
		InternalServerError(c, err)
		return
	}

	cScalar, err := share.HexToScalar(requestBody.CScalarHex, ch.nodeService.Suite)

	rValuesHex := make([]string, 0)
	for i := 1; i <= u.MyYPoly.U(); i++ {
		bp := u.MyYPoly.Eval(int64(i))
		s := share.GenerateRScalar(ch.nodeService.Suite, wScalar, cScalar, bp)
		h, err := share.ScalarToHex(s)
		if err != nil {
			InternalServerError(c, err)
			return
		}
		rValuesHex = append(rValuesHex, h)
	}
	c.JSON(http.StatusOK,interfaces.VerifyChallengeResponse{
		UserId:     u.Id,
		RScalarHex: rValuesHex,
	})

}

func (ch *Checker) runDaemon() error {
	panic("impl me!")
}

func (ch *Checker) stopDaemon() error {
	panic("impl me!")
}
