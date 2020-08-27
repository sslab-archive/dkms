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

	"dkms/types"

	"go.dedis.ch/kyber/v3"
)

type BiPoly struct {
	g       kyber.Group // Cryptographic group
	secret  kyber.Scalar
	xCoeffs []kyber.Scalar // Coefficients of X the polynomial
	yCoeffs []kyber.Scalar // Coefficients of Y the polynomial
}

type CommitData struct {
	g            kyber.Group // Cryptographic group
	h            kyber.Point // Base point
	secretCommit kyber.Point
	xCommits     []kyber.Point // Commitments to coefficients of the secret sharing polynomial
	yCommits     []kyber.Point // Commitments to coefficients of the secret sharing polynomial
}

func (c *CommitData) Marshal() (*types.CommitData, error) {
	secretCommitStr, err := PointToHex(c.secretCommit)
	if err != nil {
		return nil, err
	}

	baseStr, err := PointToHex(c.h)
	if err != nil {
		return nil, err
	}

	XCommit := make([]string, len(c.xCommits))
	YCommit := make([]string, len(c.yCommits))
	for _, v := range c.xCommits {
		str, err := PointToHex(v)
		if err != nil {
			return nil, err
		}

		XCommit = append(XCommit, str)
	}

	for _, v := range c.yCommits {
		str, err := PointToHex(v)
		if err != nil {
			return nil, err
		}

		YCommit = append(YCommit, str)
	}

	d := &types.CommitData{
		BasePointHex:    baseStr,
		SecretCommitHex: secretCommitStr,
		XCommitsHex:     XCommit,
		YCommitsHex:     YCommit,
	}

	return d, nil
}

func (c *CommitData) UnMarshal(rawData types.CommitData) error {
	var err error
	c.secretCommit, err = HexToPoint(rawData.SecretCommitHex, c.g)
	if err != nil {
		return err
	}

	c.h, err = HexToPoint(rawData.BasePointHex, c.g)
	if err != nil {
		return err
	}

	xCommit := make([]kyber.Point, len(rawData.XCommitsHex))
	for i, v := range rawData.XCommitsHex {
		p, err := HexToPoint(v, c.g)
		if err != nil {
			return err
		}
		xCommit[i] = p
	}

	yCommit := make([]kyber.Point, len(rawData.YCommitsHex))
	for i, v := range rawData.YCommitsHex {
		p, err := HexToPoint(v, c.g)
		if err != nil {
			return err
		}
		yCommit[i] = p
	}

	c.xCommits = xCommit
	c.yCommits = yCommit

	return nil
}

type XPoly struct {
	g        kyber.Group // Cryptographic group
	I        int
	constant kyber.Scalar
	xCoeffs  []kyber.Scalar // Coefficients of X the polynomial
}

type YPoly struct {
	g        kyber.Group // Cryptographic group
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

func (b *BiPoly) GetXPoly(y int) *XPoly {
	yi := b.g.Scalar().SetInt64(int64(y))
	yValue := b.g.Scalar().Zero()
	for k := b.U() - 1; k >= 0; k-- {
		yValue.Mul(yValue, yi)
		yValue.Add(yValue, b.yCoeffs[k])
	}
	constant := b.g.Scalar().Zero()
	constant.Add(b.secret, yValue)
	return &XPoly{
		I:        y,
		constant: constant,
		xCoeffs:  b.xCoeffs,
	}
}

func (b *BiPoly) GetYPoly(x int) *YPoly {
	xi := b.g.Scalar().SetInt64(int64(x))
	xValue := b.g.Scalar().Zero()
	for j := b.T() - 1; j >= 0; j-- {
		xValue.Mul(xValue, xi)
		xValue.Add(xValue, b.xCoeffs[j])
	}
	constant := b.g.Scalar().Zero()
	constant.Add(b.secret, xValue)
	return &YPoly{
		I:        x,
		constant: constant,
		yCoeffs:  b.yCoeffs,
	}
}

func (xp *XPoly) Eval(x int) *BiPoint {
	xi := xp.g.Scalar().SetInt64(int64(x))
	xValue := xp.g.Scalar().Zero()
	for j := xp.T() - 1; j >= 0; j-- {
		xValue.Mul(xValue, xi)
		xValue.Add(xValue, xp.xCoeffs[j])
	}

	totalValue := xp.g.Scalar().Zero()

	totalValue.Add(xValue, xp.constant)
	return &BiPoint{x, xp.I, totalValue}
}

func (yp *YPoly) Eval(y int) BiPoint {
	yi := yp.g.Scalar().SetInt64(int64(y))
	yValue := yp.g.Scalar().Zero()
	for k := yp.U() - 1; k >= 0; k-- {
		yValue.Mul(yValue, yi)
		yValue.Add(yValue, yp.yCoeffs[k])
	}
	totalValue := yp.g.Scalar().Zero()

	totalValue.Add(yValue, yp.constant)
	return BiPoint{yp.I, y, totalValue}
}

func (b *BiPoly) Eval(x int, y int) BiPoint {
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
	return BiPoint{x, y, totalValue}
}

// T returns the secret sharing threshold.
func (b *BiPoly) T() int {
	return len(b.xCoeffs)
}

func (xp *XPoly) T() int {
	return len(xp.xCoeffs)
}

// U returns the y threshold.
func (b *BiPoly) U() int {
	return len(b.yCoeffs)
}

func (yp *YPoly) U() int {
	return len(yp.yCoeffs)
}

// Shares creates a list of n private shares h(x,1),...,p(x,n).
func (b *BiPoly) Shares(n int) []*YPoly {
	shares := make([]*YPoly, n)
	for i := range shares {
		shares[i] = b.GetYPoly(i)
	}
	return shares
}

func (b *BiPoly) Commit(bp kyber.Point) CommitData {
	xCommits := make([]kyber.Point, b.T())
	yCommits := make([]kyber.Point, b.T())

	secretCommit := b.g.Point().Mul(b.secret, bp)

	return CommitData{
		g:            b.g,
		h:            bp,
		secretCommit: secretCommit,
		xCommits:     xCommits,
		yCommits:     yCommits,
	}
}
