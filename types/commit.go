package types

type CommitData struct {
	BasePoint    string   `json:"basePoint"`
	SecretCommit string   `json:"secretCommit"`
	XCommits     []string `json:"xCommits"`
	YCommits     []string `json:"yCommits"`
}
