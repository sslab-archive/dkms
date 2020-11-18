package interfaces

type VerifyChallengeResponse struct {
	UserId     string   `json:"userId"`
	RScalarHex []string `json:"rScalarHex"`
}
type VerifyOptChallengeResponse struct {
	UserId     string   `json:"userId"`
	RScalarHex string `json:"rScalarHex"`
}