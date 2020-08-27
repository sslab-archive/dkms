package types

type CommitData struct {
	BasePointHex    string   `json:"basePointHex"`
	SecretCommitHex string   `json:"secretCommitHex"`
	XCommitsHex     []string `json:"xCommitsHex"`
	YCommitsHex     []string `json:"yCommitsHex"`
}
