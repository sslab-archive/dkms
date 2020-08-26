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

package key

import "go.dedis.ch/kyber/v3"

// Suite describes the functionalities needed by this package in order to
// function correctly.

type Suite interface {
	kyber.Group
	kyber.HashFactory
	kyber.Encoding
	kyber.XOFFactory
	kyber.Random
}

func GetPrivateKeyFromBytes(suite Suite, data []byte) (kyber.Scalar, error) {
	s := suite.Scalar()
	err := s.UnmarshalBinary(data)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func GeneratePrivateKey(suite Suite) kyber.Scalar {
	return suite.Scalar().Pick(suite.RandomStream())
}

func GetPublicKey(suite Suite, privateKey kyber.Scalar) kyber.Point {
	return suite.Point().Mul(privateKey, nil)
}
