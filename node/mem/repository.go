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

package mem

import (
	"dkms/node"
	"errors"
)

type NodeRepository struct {
	nodes map[string]node.Node
}

func NewNodeRepository() *NodeRepository {
	return &NodeRepository{
		nodes: make(map[string]node.Node),
	}
}

func (nr *NodeRepository) Save(data *node.Node) error {
	nr.nodes[data.ID()] = *data
	return nil
}

func (nr *NodeRepository) Get(id string) (node.Node, error) {
	n, ok := nr.nodes[id]
	if !ok {
		return n, errors.New("key not found error")
	}
	return n, nil
}
