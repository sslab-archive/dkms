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
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"go.dedis.ch/kyber/v3"
)

type BiPoly struct {
	G       kyber.Group // Cryptographic group
	Secret  kyber.Scalar
	XCoeffs []kyber.Scalar // Coefficients of X the polynomial
	YCoeffs []kyber.Scalar // Coefficients of Y the polynomial
}

type CommitData struct {
	G            kyber.Group // Cryptographic group
	H            kyber.Point // Base point
	SecretCommit kyber.Point
	XCommits     []kyber.Point // Commitments to coefficients of the Secret sharing polynomial
	YCommits     []kyber.Point // Commitments to coefficients of the Secret sharing polynomial
}

type XPoly struct {
	g        kyber.Group // Cryptographic group
	Y        int64
	constant kyber.Scalar
	xCoeffs  []kyber.Scalar // Coefficients of X the polynomial
}

type YPoly struct {
	g        kyber.Group // Cryptographic group
	X        int64
	constant kyber.Scalar
	yCoeffs  []kyber.Scalar // Coefficients of Y the polynomial
}

type BiPoint struct {
	X int64
	Y int64
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
	return &BiPoly{
		G:       group,
		Secret:  s,
		XCoeffs: xCoeffs,
		YCoeffs: yCoeffs,
	}, nil
}

func (b *BiPoly) GetXPoly(y int64) *XPoly {
	yi := b.G.Scalar().SetInt64(int64(y))
	yValue := b.G.Scalar().Zero()
	for k := b.U() - 2; k >= 0; k-- {
		yValue.Mul(yValue, yi)
		yValue.Add(yValue, b.YCoeffs[k])
	}
	constant := b.G.Scalar().Zero()
	constant.Add(b.Secret, yValue)
	return &XPoly{
		g:        b.G,
		Y:        y,
		constant: constant,
		xCoeffs:  b.XCoeffs,
	}
}

func (b *BiPoly) GetYPoly(x int64) *YPoly {
	xi := b.G.Scalar().SetInt64(int64(x))
	xValue := b.G.Scalar().Zero()
	for j := b.T() - 2; j >= 0; j-- {
		xValue.Mul(xValue, xi)
		xValue.Add(xValue, b.XCoeffs[j])
	}
	constant := b.G.Scalar().Zero()
	constant.Add(b.Secret, xValue)
	return &YPoly{
		g:        b.G,
		X:        x,
		constant: constant,
		yCoeffs:  b.YCoeffs,
	}
}

func (b *BiPoly) Eval(x int64, y int64) BiPoint {
	xi := b.G.Scalar().SetInt64(x)
	xValue := b.G.Scalar().Zero()
	for j := b.T() - 2; j >= 0; j-- {
		xValue.Add(xValue, b.XCoeffs[j])
		xValue.Mul(xValue, xi)
	}

	yi := b.G.Scalar().SetInt64(y)
	yValue := b.G.Scalar().Zero()
	for k := b.U() - 2; k >= 0; k-- {
		yValue.Add(yValue, b.YCoeffs[k])
		yValue.Mul(yValue, yi)
	}
	totalValue := b.G.Scalar().Zero()
	totalValue.Add(xValue, yValue)
	totalValue.Add(totalValue, b.Secret)

	return BiPoint{x, y, totalValue}
}

// T returns the Secret sharing threshold.
func (b *BiPoly) T() int {
	return len(b.XCoeffs) + 1
}

func (b *BiPoly) U() int {
	return len(b.YCoeffs) + 1
}

func (xp *XPoly) Eval(x int64) BiPoint {
	xi := xp.g.Scalar().SetInt64(x)
	xValue := xp.g.Scalar().Zero()
	for j := xp.T() - 2; j >= 0; j-- {
		xValue.Add(xValue, xp.xCoeffs[j])
		xValue.Mul(xValue, xi)
	}

	totalValue := xp.g.Scalar().Zero()

	totalValue.Add(xValue, xp.constant)
	return BiPoint{x, xp.Y, totalValue}
}

func (yp *YPoly) Eval(y int64) BiPoint {
	yi := yp.g.Scalar().SetInt64(y)
	yValue := yp.g.Scalar().Zero()
	for k := yp.U() - 2; k >= 0; k-- {
		yValue.Add(yValue, yp.yCoeffs[k])
		yValue.Mul(yValue, yi)
	}
	totalValue := yp.g.Scalar().Zero()

	totalValue.Add(yValue, yp.constant)
	return BiPoint{yp.X, y, totalValue}
}

func (xp *XPoly) T() int {
	return len(xp.xCoeffs) + 1
}

// U returns the y threshold.
func (yp *YPoly) U() int {
	return len(yp.yCoeffs) + 1
}

// Shares creates a list of n private shares h(x,1),...,p(x,n).
func (b *BiPoly) Shares(n int) []*YPoly {
	shares := make([]*YPoly, n)
	for i := range shares {
		shares[i] = b.GetYPoly(int64(i))
	}
	return shares
}

func (b *BiPoly) Commit(commitBasePoint kyber.Point) CommitData {
	xCommits := make([]kyber.Point, b.T()-1)
	yCommits := make([]kyber.Point, b.U()-1)

	secretCommit := b.G.Point().Mul(b.Secret, commitBasePoint)

	for i := 0; i < b.T()-1; i++ {
		xCommits[i] = b.G.Point().Mul(b.XCoeffs[i], commitBasePoint)
	}
	for i := 0; i < b.U()-1; i++ {
		yCommits[i] = b.G.Point().Mul(b.YCoeffs[i], commitBasePoint)
	}
	return CommitData{
		G:            b.G,
		H:            commitBasePoint,
		SecretCommit: secretCommit,
		XCommits:     xCommits,
		YCommits:     yCommits,
	}
}

func LagrangeForYPoly(g kyber.Group, points []BiPoint, u int) (*YPoly, error) {
	x := points[0].X
	for _, p := range points {
		if x != p.X {
			return nil, errors.New("not matched point")
		}
	}
	points = points[:u]
	var accPoly *PriPoly
	var err error
	for j := range points {
		basis := lagrangeForYPolyBasis(g, j, points)
		for i := range basis.coeffs {
			basis.coeffs[i] = basis.coeffs[i].Mul(basis.coeffs[i], points[j].V)
		}

		if accPoly == nil {
			accPoly = basis
			continue
		}

		accPoly, err = accPoly.Add(basis)
		if err != nil {
			return nil, err
		}
	}
	if accPoly == nil {
		return nil, errors.New("acc poly nil error")
	}
	return &YPoly{
		g:        g,
		X:        x,
		constant: accPoly.coeffs[0],
		yCoeffs:  accPoly.coeffs[1:],
	}, nil

}

func LagrangeForXPoly(g kyber.Group, points []BiPoint, t int) (*XPoly, error) {
	y := points[0].Y
	for _, p := range points {
		if y != p.Y {
			return nil, errors.New("not matched point")
		}
	}
	points = points[:t]
	var accPoly *PriPoly
	var err error
	for j := range points {
		basis := lagrangeForXPolyBasis(g, j, points)
		for i := range basis.coeffs {
			basis.coeffs[i] = basis.coeffs[i].Mul(basis.coeffs[i], points[j].V)
		}

		if accPoly == nil {
			accPoly = basis
			continue
		}

		accPoly, err = accPoly.Add(basis)
		if err != nil {
			return nil, err
		}
	}
	if accPoly == nil {
		return nil, errors.New("acc poly nil error")
	}
	return &XPoly{
		g:        g,
		Y:        y,
		constant: accPoly.coeffs[0],
		xCoeffs:  accPoly.coeffs[1:],
	}, nil

}

func lagrangeForXPolyBasis(g kyber.Group, i int, xs []BiPoint) *PriPoly {
	var basis = &PriPoly{
		g:      g,
		coeffs: []kyber.Scalar{g.Scalar().One()},
	}
	// compute lagrange basis l_j
	den := g.Scalar().One()
	var acc = g.Scalar().One()
	for m, xm := range xs {
		if i == m {
			continue
		}
		basis = basis.Mul(minusConst(g, g.Scalar().SetInt64(xm.X)))
		den.Sub(g.Scalar().SetInt64(xs[i].X), g.Scalar().SetInt64(xm.X)) // den = xi - xm
		den.Inv(den)                                                     // den = 1 / den
		acc.Mul(acc, den)                                                // acc = acc * den
	}

	// multiply all coefficients by the denominator
	for i := range basis.coeffs {
		basis.coeffs[i] = basis.coeffs[i].Mul(basis.coeffs[i], acc)
	}
	return basis
}

func lagrangeForYPolyBasis(g kyber.Group, i int, ys []BiPoint) *PriPoly {
	var basis = &PriPoly{
		g:      g,
		coeffs: []kyber.Scalar{g.Scalar().One()},
	}
	// compute lagrange basis l_j
	den := g.Scalar().One()
	var acc = g.Scalar().One()
	for m, ym := range ys {
		if i == m {
			continue
		}
		basis = basis.Mul(minusConst(g, g.Scalar().SetInt64(ym.Y)))
		den.Sub(g.Scalar().SetInt64(ys[i].Y), g.Scalar().SetInt64(ym.Y)) // den = xi - xm
		den.Inv(den)                                                     // den = 1 / den
		acc.Mul(acc, den)                                                // acc = acc * den
	}

	// multiply all coefficients by the denominator
	for i := range basis.coeffs {
		basis.coeffs[i] = basis.coeffs[i].Mul(basis.coeffs[i], acc)
	}
	return basis
}

func minusConst(g kyber.Group, c kyber.Scalar) *PriPoly {
	neg := g.Scalar().Neg(c)
	return &PriPoly{
		g:      g,
		coeffs: []kyber.Scalar{neg, g.Scalar().One()},
	}
}

type PriPoly struct {
	g      kyber.Group    // Cryptographic group
	coeffs []kyber.Scalar // Coefficients of the polynomial
}

func (p *PriPoly) Mul(q *PriPoly) *PriPoly {
	d1 := len(p.coeffs) - 1
	d2 := len(q.coeffs) - 1
	newDegree := d1 + d2
	coeffs := make([]kyber.Scalar, newDegree+1)
	for i := range coeffs {
		coeffs[i] = p.g.Scalar().Zero()
	}
	for i := range p.coeffs {
		for j := range q.coeffs {
			tmp := p.g.Scalar().Mul(p.coeffs[i], q.coeffs[j])
			coeffs[i+j] = tmp.Add(coeffs[i+j], tmp)
		}
	}
	return &PriPoly{p.g, coeffs}
}

// as a new polynomial.
func (p *PriPoly) Add(q *PriPoly) (*PriPoly, error) {
	if p.g.String() != q.g.String() {
		return nil, errors.New("not matched group")
	}
	if len(p.coeffs) != len(q.coeffs) {
		return nil, errors.New("not matched coeffs length in poly add")
	}
	coeffs := make([]kyber.Scalar, len(p.coeffs))
	for i := range coeffs {
		coeffs[i] = p.g.Scalar().Add(p.coeffs[i], q.coeffs[i])
	}
	return &PriPoly{p.g, coeffs}, nil
}

func ScalarToInt(s kyber.Scalar) (int64, error) {
	var r int64
	b, err := s.MarshalBinary()
	if err != nil {
		return -1, err
	}

	reader := bytes.NewReader(b)
	err = binary.Read(reader, binary.LittleEndian, &r)
	if err != nil {
		return -1, err
	}
	return r, nil
}
