package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"dkms/checker"
	"dkms/node"
	"dkms/server/interfaces"
	"dkms/share"
	"dkms/user"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

type Checker struct {
	userRepository       user.Repository
	checkerLogRepository checker.LogRepository
	nodeService          *node.Service
	daemonCtx            *context.Context
	daemonCancelFunc     *context.CancelFunc
}

func NewChecker(userRepository user.Repository, checkerLogRepository checker.LogRepository, nodeService *node.Service) *Checker {
	return &Checker{
		userRepository:       userRepository,
		nodeService:          nodeService,
		checkerLogRepository: checkerLogRepository,
	}
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
	u.Monitoring = true
	err = ch.userRepository.Save(&u)
	if err != nil {
		InternalServerError(c, err)
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
	u, err := ch.userRepository.Get(requestBody.UserId)
	if err != nil {
		BadRequestError(c, errors.New("body variable user does not exists"))
		return
	}

	u.Monitoring = false
	err = ch.userRepository.Save(&u)
	if err != nil {
		InternalServerError(c, err)
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

	wScalar, err := share.HexToScalar(requestBody.WScalarHex, ch.nodeService.Suite)
	if err != nil {
		InternalServerError(c, err)
		return
	}

	cScalar, err := share.HexToScalar(requestBody.CScalarHex, ch.nodeService.Suite)

	bp := u.MyYPoly.Eval(int64(1))
	s := share.GenerateRScalar(ch.nodeService.Suite, wScalar, cScalar, bp)

	rValuesHex, err := share.ScalarToHex(s)
	if err != nil {
		InternalServerError(c, err)
		return
	}
	c.JSON(http.StatusOK, interfaces.VerifyOptChallengeResponse{
		UserId:     u.Id,
		RScalarHex: rValuesHex,
	})

}

func (ch *Checker) StartChecking(c *gin.Context) {
	go func() {
		_ = ch.runDaemon()
	}()

	c.JSON(http.StatusNoContent, nil)
	return
}

func (ch *Checker) StopChecking(c *gin.Context) {
	err := ch.stopDaemon()

	if err != nil {
		InternalServerError(c, err)
	}
	c.JSON(http.StatusNoContent, nil)
	return
}

func (ch *Checker) runDaemon() error {
	if ch.daemonCtx != nil {
		return errors.New("daemon is already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	ch.daemonCtx = &ctx
	ch.daemonCancelFunc = &cancel
	done := make(chan string)
	go func(resultChannel chan string, ctx context.Context) {
		for ctx != nil {
			users, err := ch.userRepository.GetAllMonitoringUser()
			if err != nil {
				logrus.Error("error while getting user info in daemon")
				logrus.Error("stop 3 sec daemon")
				time.Sleep(time.Second * 3)
				continue
			}

			// warning for empty user list
			if len(users) == 0 {
				logrus.Warn("Empty monitoring user list")
			}

			// checking user
			for _, u := range users {
				logrus.Info(fmt.Sprintf("start checking for user : %s. node len : %d", u.Id, len(u.Nodes)))
				for _, oneNode := range u.Nodes {
					// skipping for me
					if oneNode.PubKey.Equal(ch.nodeService.GetMyPublicKey()) {
						continue
					}
					// skipping for corrupted
					if oneNode.Status == node.CORRUPTED {
						logrus.Info(fmt.Sprintf("skipping coururpted node checking. user : %s, node address : %s", u.Id, oneNode.Address.Address()))
						continue
					}
					logrus.Info(fmt.Sprintf("start checking for node : " + oneNode.Address.Address()))

					logBuilder := checker.NewLogBuilder()
					logBuilder.SetFromNodeId(ch.nodeService.GetMyId()).SetTargetNodeId(oneNode.ID()).SetUserId(u.Id)
					// phase 1. get w value
					url := "http://" + oneNode.Address.Address() + "/checker/user/startVerify"
					b, err := json.Marshal(interfaces.StartVerifyRequest{UserId: u.Id})
					if err != nil {
						logrus.Error(err.Error())
						logBuilder.SetError(err)
						ch.markNodeAsCorrupted(&u, oneNode, logBuilder.Build())
						continue
					}

					resp1, err := http.Post(url, "application/json", bytes.NewReader(b))
					if err != nil {
						logrus.Error(err.Error())
						logBuilder.SetError(err)
						ch.markNodeAsCorrupted(&u, oneNode, logBuilder.Build())
						continue
					}

					b1, err := ioutil.ReadAll(resp1.Body)
					r1 := interfaces.StartVerifyResponse{}
					err = json.Unmarshal(b1, &r1)
					if err != nil {
						logrus.Error(err.Error())
						logBuilder.SetError(err)
						ch.markNodeAsCorrupted(&u, oneNode, logBuilder.Build())
						continue
					}
					logBuilder.SetW(r1.WScalarHex)

					w, err := share.HexToScalar(r1.WScalarHex, ch.nodeService.Suite)
					if err != nil {
						logrus.Error(err.Error())
						logBuilder.SetError(err)
						ch.markNodeAsCorrupted(&u, oneNode, logBuilder.Build())
						continue
					}
					logrus.Info(fmt.Sprintf("received W value : %s", r1.WScalarHex))

					// phase 2. make c -> send w, c -> get r value
					randomCVal := share.GenerateCScalar(ch.nodeService.Suite)
					c, err := share.ScalarToHex(randomCVal)
					if err != nil {
						logrus.Error(err.Error())
						logBuilder.SetError(err)
						ch.markNodeAsCorrupted(&u, oneNode, logBuilder.Build())
						continue
					}
					logBuilder.SetC(c)

					logrus.Info(fmt.Sprintf("generated C value : %s", c))
					url = "http://" + oneNode.Address.Address() + "/checker/user/challenge"
					b, err = json.Marshal(interfaces.VerifyChallengeRequest{
						UserId:     u.Id,
						CScalarHex: c,
						WScalarHex: r1.WScalarHex,
					})
					if err != nil {
						logrus.Error(err.Error())
						logBuilder.SetError(err)
						ch.markNodeAsCorrupted(&u, oneNode, logBuilder.Build())
						continue
					}

					resp2, err := http.Post(url, "application/json", bytes.NewReader(b))
					if err != nil {
						logrus.Error(err.Error())
						logBuilder.SetError(err)
						ch.markNodeAsCorrupted(&u, oneNode, logBuilder.Build())
						continue
					}

					b2, err := ioutil.ReadAll(resp2.Body)

					r2 := interfaces.VerifyOptChallengeResponse{}
					err = json.Unmarshal(b2, &r2)
					if err != nil {
						logrus.Error(err.Error())
						logBuilder.SetError(err)
						ch.markNodeAsCorrupted(&u, oneNode, logBuilder.Build())
						continue
					}
					r, err := share.HexToScalar(r2.RScalarHex, ch.nodeService.Suite)
					if err != nil {
						logrus.Error(err.Error())
						logBuilder.SetError(err)
						ch.markNodeAsCorrupted(&u, oneNode, logBuilder.Build())
						break
					}
					logBuilder.SetR(r2.RScalarHex)
					result := share.VerifyOptRScalar(ch.nodeService.Suite, w, randomCVal, r, oneNode.Index, 1, oneNode.PubKey, u.PolyCommit, oneNode.EncryptedPoints[0])
					if result {
						logrus.Info(fmt.Sprintf("R : %s -------> success", r2.RScalarHex))
					} else {
						logrus.Info(fmt.Sprintf("R : %s -------> fail",  r2.RScalarHex))
						logBuilder.SetError(errors.New("r value verification fail"))
						ch.markNodeAsCorrupted(&u, oneNode, logBuilder.Build())
					}
					logrus.Info(fmt.Sprintf("finish checking node : %s", oneNode.Address.Address()))
					logrus.Info("--------------------------------------------------------------")

				}
				logrus.Info(fmt.Sprintf("finish checking user : %s. rest for 1 sec...", u.Id))
				logrus.Info("--------------------------------------------------------------")
				time.Sleep(time.Second)
			}
			logrus.Info(fmt.Sprintf("finish checking one cycle (all user). rest for 3 sec..."))
			logrus.Info("--------------------------------------------------------------")
			time.Sleep(time.Second * 3)
		}
		logrus.Info("damon is shut down in goroutine")
	}(done, ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (ch *Checker) GetMyLogs(c *gin.Context) {
	addr := ch.nodeService.GetMyAddress()
	logs := ch.checkerLogRepository.GetLogsByFromNodeId(addr.Address())[:50]
	c.JSON(http.StatusOK, logs)
	return
}

func (ch *Checker) GetTargetLogs(c *gin.Context) {

	var pathParams struct {
		Id string `uri:"id" binding:"required"`
	}

	if err := c.ShouldBindUri(&pathParams); err != nil {
		BadRequestError(c, errors.New("path variable :id does not exists"))
		return
	}

	logs := ch.checkerLogRepository.GetLogsByTargetNodeIds(pathParams.Id)
	c.JSON(http.StatusOK, logs)
	return
}

func (ch *Checker) stopDaemon() error {
	if ch.daemonCancelFunc == nil {
		return errors.New("there is no daemon to stop")
	}
	(*ch.daemonCancelFunc)()
	ch.daemonCtx = nil
	ch.daemonCancelFunc = nil
	return nil
}

func (ch *Checker) markNodeAsCorrupted(u *user.User, oneNode *node.Node, log *checker.Log) {
	oneNode.Status = node.CORRUPTED
	err := ch.userRepository.Save(u)
	ch.checkerLogRepository.Add(*log)
	if err != nil {
		logrus.Error("error while user set as corrupted in markNodeAsCorrupted")
	}
}
