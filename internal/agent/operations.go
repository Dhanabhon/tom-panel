package agent

import (
	"context"
	"encoding/json"
	"path/filepath"

	"github.com/Dhanabhon/tom-panel/internal/agentapi"
)

func dispatch(ctx context.Context, request agentapi.Request) (json.RawMessage, *agentapi.Error) {
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
	case "site.ensure_identity":
		result, err := ensureIdentity(ctx, request.Payload)
		return operationResult(result, err)
	case "site.ensure_directories":
		result, err := ensureDirectories(ctx, request.Payload, siteRootPath)
		if err == nil {
			err = setDirectoryOwner(filepath.Base(result.SiteRoot), siteRootPath)
		}
		return operationResult(result, err)
	case "nginx.validate_activate":
		var input nginxActivateInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, activateNginx(ctx, input, defaultNginxEnvironment()))
	case "nginx.disable":
		var input siteInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, disableNginx(ctx, input, defaultNginxEnvironment()))
	case "ufw.ensure_rule":
		var input ufwInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, ensureUFW(ctx, input))
	case "ufw.remove_owned_rule":
		var input ufwInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, removeOwnedUFW(ctx, input))
	case "certificate.issue":
		var input certificateIssueInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		result, err := issueCertificate(ctx, input)
		return operationResult(result, err)
	case "certificate.activate":
		var input certificateActivateInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		result, err := activateCertificate(ctx, input)
		return operationResult(result, err)
	default:
		return nil, &agentapi.Error{Code: "operation_not_allowed", Message: "operation is not allowed"}
	}
}

func operationResult(result any, err error) (json.RawMessage, *agentapi.Error) {
	if err != nil {
		return nil, &agentapi.Error{Code: "operation_failed", Message: err.Error()}
	}
	return marshalResult(result)
}

func invalidPayload(operation string) (json.RawMessage, *agentapi.Error) {
	return nil, &agentapi.Error{Code: "invalid_payload", Message: operation + " payload is invalid"}
}

func marshalResult(result any) (json.RawMessage, *agentapi.Error) {
	payload, err := json.Marshal(result)
	if err != nil {
		return nil, &agentapi.Error{Code: "internal_error", Message: "agent could not encode the result"}
	}
	return payload, nil
}
