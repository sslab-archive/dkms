package mem

import (
	"dkms/checker"
)

type CheckerLogRepository struct {
	data []checker.Log
}

func NewCheckerLogRepository() *CheckerLogRepository {
	return &CheckerLogRepository{data: make([]checker.Log, 0)}
}

func (c *CheckerLogRepository) Add(log checker.Log) {
	c.data = append(c.data, log)
}

func (c *CheckerLogRepository) GetLogsByUserId(userId string) []checker.Log {
	res := make([]checker.Log, 0)
	for _, d := range c.data {
		if d.UserId == userId {
			res = append(res, d)
		}
	}
	return reverse(res)
}

func (c *CheckerLogRepository) GetLogsByFromNodeId(nodeId string) []checker.Log {
	res := make([]checker.Log, 0)
	for _, d := range c.data {
		if d.FromNodeId == nodeId {
			res = append(res, d)
		}
	}
	return reverse(res)
}

func (c *CheckerLogRepository) GetLogsByTargetNodeIds(nodeId string) []checker.Log {
	res := make([]checker.Log, 0)
	for _, d := range c.data {
		if d.TargetNodeId == nodeId {
			res = append(res, d)
		}
	}
	return reverse(res)
}

func (c *CheckerLogRepository) GetAllLogs() []checker.Log {
	return c.data
}


func reverse(logs []checker.Log) []checker.Log {
	newLogs := make([]checker.Log, 0, len(logs))
	for i := len(logs)-1; i >= 0; i-- {
		newLogs = append(newLogs, logs[i])
	}
	return newLogs
}