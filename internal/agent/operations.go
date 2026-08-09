package agent

import (
	"encoding/json"

	"github.com/Dhanabhon/tom-panel/internal/agentapi"
)

func dispatch(request agentapi.Request) (json.RawMessage, *agentapi.Error) {
	switch request.Operation {
	case "system.inspect":
		return marshalResult(struct {
			Status string `json:"status"`
		}{Status: "ok"})
	case "job.demo":
		var input struct {
			Message string `json:"message"`
		}
		if err := json.Unmarshal(request.Payload, &input); err != nil {
			return nil, &agentapi.Error{Code: "invalid_payload", Message: "job.demo payload is invalid"}
		}
		return marshalResult(input)
	default:
		return nil, &agentapi.Error{Code: "operation_not_allowed", Message: "operation is not allowed"}
	}
}

func marshalResult(result any) (json.RawMessage, *agentapi.Error) {
	payload, err := json.Marshal(result)
	if err != nil {
		return nil, &agentapi.Error{Code: "internal_error", Message: "agent could not encode the result"}
	}
	return payload, nil
}
