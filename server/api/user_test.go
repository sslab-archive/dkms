package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"dkms/server/interfaces"
	"dkms/server/types"
	"dkms/share"
	"dkms/user/mem"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

func TestUser_RegisterUser(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	serverPrivateKey := suite.Scalar().Pick(suite.RandomStream())
	privateKeyBinary, err := serverPrivateKey.MarshalBinary()
	assert.NoError(t, err)

	repo := mem.NewUserRepository()
	shareService, err := share.NewService(suite, privateKeyBinary)
	assert.NoError(t, err)

	secret := suite.Scalar().Pick(suite.RandomStream())
	T := 3
	U := 3
	H := suite.Point().Pick(suite.XOF([]byte("H")))
	biPoly, err := share.NewBiPoly(suite, T, U, secret, suite.RandomStream())
	assert.NoError(t, err)

	rawPoints := make([]share.BiPoint, 0)
	yPoly := biPoly.GetYPoly(1)
	xPoly := biPoly.GetXPoly(1)
	for i := int64(1); i < int64(U+1); i++ {
		yp := yPoly.Eval(i)
		rawPoints = append(rawPoints, yp)
	}

	for i := int64(1); i < int64(T+1); i++ {
		xp := xPoly.Eval(i)
		rawPoints = append(rawPoints, xp)
	}
	assert.NoError(t, err)

	encMsg, err := shareService.PointsToEncryptedMessage(rawPoints)
	assert.NoError(t, err)

	commitData := biPoly.Commit(H)
	typeCommit, err := types.NewPolyCommitData(commitData)
	assert.NoError(t, err)

	reqBody := interfaces.KeyRegisterRequest{
		UserId:        "hea9549",
		EncryptedData: *encMsg,
		Nodes:         make([]types.Node, 0),
		CommitData:    *typeCommit,
		T:             T,
		U:             U,
	}

	jsonRequest, err := json.Marshal(reqBody)
	assert.NoError(t, err)

	req := httptest.NewRequest("POST", "TESTUSER", bytes.NewReader(jsonRequest))
	w := httptest.NewRecorder()
	api := NewUser(repo, *shareService)

	router := gin.New()
	router.Handle(http.MethodPost, "TESTUSER", api.RegisterUser)
	router.ServeHTTP(w, req)

	fmt.Println(w.Body)

}
