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

package checker

import (
	"dkms/user"
	"errors"
)

type Service struct {
	checkUsers map[string]user.User
}

func NewService() *Service {
	return &Service{
		checkUsers: make(map[string]user.User),
	}
}
func (s *Service) AddCheckUser(user user.User) error {
	if _,ok := s.checkUsers[user.Id]; ok{
		return errors.New("already existed user")
	}
	s.checkUsers[user.Id] = user
	return nil
}
func (s *Service) RemoveCheckUser(userId string) error {
	if _,ok := s.checkUsers[userId]; ok{
		delete(s.checkUsers,userId)
	}
	return nil
}
