package checker

import "time"

type Result = string

const (
	RESULT_SUCCESS            = "success validation"
	RESULT_FAIL_W             = "fail w"
	RESULT_FAIL_C             = "fail c"
	RESULT_FAIL_R             = "fail r"
	RESULT_FAIL_VERIFIACATION = "fail verification"
)

type Log struct {
	UserId       string
	FromNodeId   string
	TargetNodeId string
	WHex         string
	CHex         string
	RHex         string
	Result       Result
	ErrorMsg     string
	Time         time.Time
}

type LogBuilder struct {
	resultLog *Log
}

func NewLogBuilder() *LogBuilder {
	return &LogBuilder{
		resultLog: &Log{
			Time: time.Now(),
		},
	}
}
func (lb *LogBuilder) SetUserId(userId string) *LogBuilder {
	lb.resultLog.UserId = userId
	return lb
}

func (lb *LogBuilder) SetFromNodeId(id string) *LogBuilder {
	lb.resultLog.FromNodeId = id
	return lb
}

func (lb *LogBuilder) SetTargetNodeId(id string) *LogBuilder {
	lb.resultLog.TargetNodeId = id
	return lb
}

func (lb *LogBuilder) SetW(hexData string) *LogBuilder {
	lb.resultLog.WHex = hexData
	return lb
}
func (lb *LogBuilder) SetC(hexData string) *LogBuilder {
	lb.resultLog.CHex = hexData
	return lb
}
func (lb *LogBuilder) SetR(hexData string) *LogBuilder {
	lb.resultLog.RHex = hexData
	return lb
}
func (lb *LogBuilder) SetError(err error) *LogBuilder {
	lb.resultLog.ErrorMsg = err.Error()
	return lb
}
func (lb *LogBuilder) Build() *Log {
	if lb.resultLog.ErrorMsg == "" {
		lb.resultLog.Result = RESULT_SUCCESS
	} else {
		lb.resultLog.Result = RESULT_FAIL_VERIFIACATION
	}
	if lb.resultLog.WHex == "" {
		lb.resultLog.Result = RESULT_FAIL_W
	} else if lb.resultLog.CHex == "" {
		lb.resultLog.Result = RESULT_FAIL_C
	} else if lb.resultLog.RHex == "" {
		lb.resultLog.Result = RESULT_FAIL_R
	}
	return lb.resultLog
}
