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
	"go.dedis.ch/kyber/v3"
)

type Address struct {
	Ip   string `json:"ip"`
	Port string `json:"port"`
}

func (a *Address) Address() string {
	return a.Ip+":"+a.Port
}
type Status = string

const (
	AVAILABLE = Status("AVAILABLE")
	CORRUPTED = Status("CORRUPTED")
)

func NewNode(index int, addr Address) *Node {
	return &Node{
		id:              addr.Address(),
		PubKey:          nil,
		Address:         addr,
		Index:           index,
		EncryptedPoints: make([]kyber.Point, 0),
		Status:          AVAILABLE,
	}
}

type Node struct {
	id              string
	PubKey          kyber.Point
	Address         Address
	Index           int
	EncryptedPoints []kyber.Point
	Status          Status
}

func (d *Node) ID() string {
	return d.id
}
