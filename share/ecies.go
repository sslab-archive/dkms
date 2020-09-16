package share

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"



	"go.dedis.ch/kyber/v3"
)

type EncryptedMessage struct {
	SharedPublicPointHex string
	MsgHex               string
	NonceHex             string
}


func Encrypt(suite Suite, pubKey kyber.Point, msg []byte) (*EncryptedMessage, error) {

	sharePrivateKey := suite.Scalar().Pick(suite.RandomStream())
	sharePublicKey := suite.Point().Mul(sharePrivateKey, nil)

	sharePublicKeyHex, err := PointToHex(sharePublicKey)
	if err != nil {
		return nil, err

	}

	shareEncryptKey := suite.Point().Mul(sharePrivateKey, pubKey)
	shareEncryptKeyHex, err := PointToHex(shareEncryptKey)
	if err != nil {
		return nil, err

	}

	block, err := aes.NewCipher([]byte(shareEncryptKeyHex)[:32])
	if err != nil {
		return nil, err

	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot read random bytes for nonce: %w", err)
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err

	}

	cipherText := aesgcm.Seal(nil, nonce, msg, nil)
	return &EncryptedMessage{
		SharedPublicPointHex: sharePublicKeyHex,
		MsgHex:               hex.EncodeToString(cipherText),
		NonceHex:             hex.EncodeToString(nonce),
	}, nil
}

func Decrypt(suite Suite, privateKey kyber.Scalar, encryptedMsg EncryptedMessage) ([]byte, error) {
	sharePublicKey, err := HexToPoint(encryptedMsg.SharedPublicPointHex, suite)
	if err != nil {
		return nil, err
	}

	shareEncryptKey := suite.Point().Mul(privateKey, sharePublicKey)

	shareEncryptKeyHex, err := PointToHex(shareEncryptKey)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher([]byte(shareEncryptKeyHex)[:32])
	aesgcm, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err

	}

	nonce, err := hex.DecodeString(encryptedMsg.NonceHex)
	if err != nil {
		return nil, err

	}

	cipherMsg, err := hex.DecodeString(encryptedMsg.MsgHex)
	if err != nil {
		return nil, err

	}

	plainText, err := aesgcm.Open(nil, nonce, cipherMsg, nil)
	if err != nil {
		return nil, err

	}

	return plainText, nil
}
