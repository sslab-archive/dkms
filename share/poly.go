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
	"crypto/cipher"
	"errors"
	"go.dedis.ch/kyber/v3"
)

type BiPoly struct {
	g       kyber.Group // Cryptographic group
	secret  kyber.Scalar
	xCoeffs []kyber.Scalar // Coefficients of X the polynomial
	yCoeffs []kyber.Scalar // Coefficients of Y the polynomial
}

type XPoly struct {
	I        int
	constant kyber.Scalar
	xCoeffs  []kyber.Scalar // Coefficients of X the polynomial
}

type YPoly struct {
	I        int
	constant kyber.Scalar
	yCoeffs  []kyber.Scalar // Coefficients of Y the polynomial
}

type BiPoint struct {
	X int
	Y int
	V kyber.Scalar
}

func NewBiPoly(group kyber.Group, t int, u int, s kyber.Scalar, rand cipher.Stream) (*BiPoly, error) {

	if s == nil {
		return nil, errors.New("비밀값을 입력하지 않았습니다")
	}

	xCoeffs := make([]kyber.Scalar, t-1)
	for i := 0; i < t-1; i++ {
		xCoeffs[i] = group.Scalar().Pick(rand)
	}

	yCoeffs := make([]kyber.Scalar, u-1)
	for i := 0; i < u-1; i++ {
		yCoeffs[i] = group.Scalar().Pick(rand)
	}
	return &BiPoly{g: group, xCoeffs: xCoeffs, yCoeffs: yCoeffs}, nil
}

func (b *BiPoly) Eval(x int, y int) *BiPoint {
	xi := b.g.Scalar().SetInt64(int64(x))
	xValue := b.g.Scalar().Zero()
	for j := b.T() - 1; j >= 0; j-- {
		xValue.Mul(xValue, xi)
		xValue.Add(xValue, b.xCoeffs[j])
	}

	yi := b.g.Scalar().SetInt64(int64(y))
	yValue := b.g.Scalar().Zero()
	for k := b.U() - 1; k >= 0; k-- {
		yValue.Mul(yValue, yi)
		yValue.Add(yValue, b.yCoeffs[k])
	}
	totalValue := b.g.Scalar().Zero()

	totalValue.Add(xValue, yValue)
	return &BiPoint{x, y, totalValue}
}

func (b *BiPoly) GetXPoly(y int) *XPoly {
	panic("impl me!")
}


func (b *BiPoly) GetYPoly(x int) *YPoly {
	panic("impl me!")
}

// T returns the secret sharing threshold.
func (b *BiPoly) T() int {
	return len(b.xCoeffs)
}

// U returns the y threshold.
func (b *BiPoly) U() int {
	return len(b.yCoeffs)
}

// Shares creates a list of n private shares b(x,1),...,p(x,n).
func (b *BiPoly) Shares(n int) []*YPoly {
	panic("impl me!")
	//shares := make([]*YPoly, n)
	//for i := range shares {
	//	shares[i] = b.Eval(i)
	//}
	//return shares
}
