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

package node

import (
	"dkms/share"

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


func MakeRecoveryData(yPoly share.YPoly, commitData share.CommitData, failIdx int64) *share.RecoveryData {
	return &share.RecoveryData{
		FromNodeIdx:    yPoly.X,
		FailureNodeIdx: failIdx,
		RecoveryPoint:  yPoly.Eval(failIdx),
		CommitData:     commitData,
	}
}
