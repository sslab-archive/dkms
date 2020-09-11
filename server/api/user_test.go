package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"dkms/node"
	"dkms/server/interfaces"
	"dkms/server/types"
	"dkms/share"
	"dkms/user/mem"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

func GetSamplePoly(suite node.Suite, secret kyber.Scalar) share.BiPoly {
	// make B(x,y) = secret + x + 2x^2 + 3y + 4y^2
	xCoeffs := make([]kyber.Scalar, 2)
	yCoeffs := make([]kyber.Scalar, 2)
	xCoeffs[0] = suite.Scalar().SetInt64(int64(1))
	xCoeffs[1] = suite.Scalar().SetInt64(int64(2))
	yCoeffs[0] = suite.Scalar().SetInt64(int64(3))
	yCoeffs[1] = suite.Scalar().SetInt64(int64(4))

	return share.BiPoly{
		G:       suite,
		Secret:  secret,
		XCoeffs: xCoeffs,
		YCoeffs: yCoeffs,
	}
}

func TestUser_RegisterUser(t *testing.T) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	serverPrivateKey := suite.Scalar().Pick(suite.RandomStream())
	privateKeyBinary, err := serverPrivateKey.MarshalBinary()
	assert.NoError(t, err)
	serverPublicKey := suite.Point().Mul(serverPrivateKey, nil)

	repo := mem.NewUserRepository()
	nodeService, err := node.NewService(suite, privateKeyBinary)
	assert.NoError(t, err)

	secret := suite.Scalar().SetInt64(123)
	T := 3
	U := 3
	H := suite.Point().Pick(suite.XOF([]byte("H")))
	biPoly := GetSamplePoly(suite, secret)
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

	encMsg, err := types.PointsToEncryptedMessage(rawPoints, serverPublicKey, suite)
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

	req := httptest.NewRequest("POST", "/TESTUSER", bytes.NewReader(jsonRequest))
	w := httptest.NewRecorder()
	api := NewUser(repo, *nodeService)

	router := gin.New()
	router.Handle(http.MethodPost, "/TESTUSER", api.RegisterUser)
	router.ServeHTTP(w, req)

	fmt.Println(w.Body)

}
