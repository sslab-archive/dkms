package interfaces

import "dkms/server/types"

type GetUserInformationResponse struct {
	Id           string
	CommitData   types.PolyCommitData
	IsMonitoring bool
	T            int
	U            int
	Nodes        []types.Node
	Logs         []types.CheckerLog
}
