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

package main

import (
	"encoding/hex"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

func GenPrvPub() (string, string) {
	suite := edwards25519.NewBlakeSHA256Ed25519()
	prv := suite.Scalar().Pick(suite.RandomStream())
	pub := suite.Point().Mul(prv, nil)
	prvMarshal, err := prv.MarshalBinary()
	if err != nil {
		panic(err.Error())
	}
	pubMarshal, err := pub.MarshalBinary()
	if err != nil {
		panic(err.Error())
	}
	prvStr := hex.EncodeToString(prvMarshal)
	pubStr := hex.EncodeToString(pubMarshal)
	return prvStr, pubStr
}
func main() {

}
