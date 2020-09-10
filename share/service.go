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

package share

import (
	"encoding/hex"
	"encoding/json"

	"dkms/server/types"

	"go.dedis.ch/kyber/v3"
)

type Suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.Encoding
	kyber.XOFFactory
	kyber.Random
}

type Service struct {
	Suite        Suite
	myPubKey     kyber.Point
	myPrivateKey kyber.Scalar
}

func NewService(s Suite, privateBytes []byte) (*Service, error) {
	prv := s.Scalar()
	err := prv.UnmarshalBinary(privateBytes)
	if err != nil {
		return nil, err
	}

	return &Service{
		Suite:        s,
		myPubKey:     s.Point().Mul(prv, nil),
		myPrivateKey: prv,
	}, nil
}

func (s *Service) GetMyPublicKey() kyber.Point {
	return s.myPubKey
}

func (s *Service) GetMyPrivateKey() kyber.Scalar {
	return s.myPrivateKey
}

func (s *Service) EncryptedMessageToPoints(encMessage EncryptedMessage) ([]BiPoint, error) {
	msg, err := Decrypt(s.Suite, s.myPrivateKey, encMessage)
	typePoints := make([]types.BiPoint, 0)
	err = json.Unmarshal(msg, &typePoints)

	points := make([]BiPoint, 0)

	for _, oneTypePoints := range typePoints {
		pointBytes, err := hex.DecodeString(oneTypePoints.ScalarHex)
		if err != nil {
			return nil, err
		}
		p := s.Suite.Scalar()
		err = p.UnmarshalBinary(pointBytes)
		if err != nil {
			return nil, err
		}

		points = append(points, BiPoint{
			X: oneTypePoints.X,
			Y: oneTypePoints.Y,
			V: p,
		})
	}

	if err != nil {
		return nil, err
	}

	return points, nil
}

func (s *Service) PointsToEncryptedMessage(points []BiPoint) (*EncryptedMessage, error) {
	typePoints := make([]types.BiPoint, 0)
	for _, onePoint := range points {
		b, err := onePoint.V.MarshalBinary()
		if err != nil {
			return nil, err
		}
		tp := types.BiPoint{
			X:         onePoint.X,
			Y:         onePoint.Y,
			ScalarHex: hex.EncodeToString(b),
		}
		typePoints = append(typePoints, tp)
	}
	pointsStr, err := json.Marshal(typePoints)
	if err != nil {
		return nil, err
	}
	encryptedMsg, err := Encrypt(s.Suite, s.myPubKey, pointsStr)
	if err != nil {
		return nil, err
	}

	return encryptedMsg, nil
}

func MakeRecoveryData(yPoly YPoly, commitData CommitData, failIdx int64) *RecoveryData {
	return &RecoveryData{
		FromNodeIdx:    yPoly.X,
		FailureNodeIdx: failIdx,
		RecoveryPoint:  yPoly.Eval(failIdx),
		CommitData:     commitData,
	}
}
