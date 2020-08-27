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

func NewNode(id string) *Node {
	return &Node{
		id:          id,
		NodeIdx:     0,
		PubKey:      nil,
		Address:     "",
	}
}

type Node struct {
	id          string
	NodeIdx     int
	PubKey      kyber.Point
	Address     string
}

func (d *Node) ID() string {
	return d.id
}
