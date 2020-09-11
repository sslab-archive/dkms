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
	"errors"

	"dkms/user"
)

type UserRepository struct {
	users map[string]user.User
}

func NewUserRepository() *UserRepository {
	return &UserRepository{
		users: make(map[string]user.User),
	}
}

func (ur *UserRepository) Save(data *user.User) error {
	ur.users[data.Id] = *data
	return nil
}

func (ur *UserRepository) Get(id string) (user.User, error) {
	n, ok := ur.users[id]
	if !ok {
		return n, errors.New("key not found error")
	}
	return n, nil
}

func (ur *UserRepository) GetAllMonitoringUser() ([]user.User, error) {
	resUser := make([]user.User, 0)
	for _, u := range ur.users {
		if u.Monitoring {
			resUser = append(resUser, u)
		}
	}
	return resUser, nil
}
