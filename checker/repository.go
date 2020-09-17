package checker

type LogRepository interface {
	Add(log Log)
	GetLogsByUserId(userId string) []Log
	GetLogsByFromNodeId(nodeId string) []Log
	GetLogsByTargetNodeIds(nodeId string) []Log
	GetAllLogs() []Log
}
