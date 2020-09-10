package interfaces

type VerifyChallengeResponse struct {
	UserId     string   `json:"userId"`
	RScalarHex []string `json:"rScalarHex"`
}
