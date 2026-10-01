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
	case "php.ensure_pool":
		var input phpPoolInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, ensurePHP(ctx, input, runCommand))
	case "php.activate_pool":
		var input phpPoolInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, activatePHPPool(ctx, input, phpPoolRoot(input.Version), runCommand))
	case "php.disable_pool":
		var input phpPoolInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, disablePHPPool(ctx, input, phpPoolRoot(input.Version), runCommand))
	case "php.install_extension":
		var input phpExtensionInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, installPHPExtension(ctx, input))
	case "file.grant_panel_access":
		var input siteInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, grantPanelAccess(ctx, input.SiteID))
	case "sftp.ensure_account":
		var input siteInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, ensureSFTPAccount(ctx, input.SiteID))
	case "sftp.disable_account":
		var input siteInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, disableSFTPAccount(ctx, input.SiteID))
	case "sftp.rotate_password":
		var input sftpPasswordInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, rotateSFTPPassword(ctx, input))
	case "sftp.add_key":
		var input sftpKeyInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		result, err := addSFTPKey(ctx, input)
		return operationResult(result, err)
	case "sftp.remove_key":
		var input sftpKeyInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, removeSFTPKey(ctx, input))
	case "mariadb.ensure_database":
		var input mariadbDatabaseInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, ensureMariaDBDatabase(ctx, input, defaultMariaDBEnvironment()))
	case "mariadb.rotate_user":
		var input mariadbRotateInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, rotateMariaDBUser(ctx, input, defaultMariaDBEnvironment()))
	case "mariadb.verify_credential":
		var input mariadbCredentialInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, verifyMariaDBCredential(ctx, input, defaultMariaDBEnvironment()))
	case "mariadb.dump":
		var input mariadbDatabaseInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		result, err := dumpMariaDBDatabase(ctx, input, defaultMariaDBEnvironment())
		return operationResult(result, err)
	case "mariadb.restore":
		var input mariadbRestoreInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, restoreMariaDBDatabase(ctx, input, defaultMariaDBEnvironment()))
	case "mariadb.drop_database":
		var input mariadbDropInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, dropMariaDBDatabase(ctx, input, defaultMariaDBEnvironment()))
	case "phpmyadmin.install":
		var input phpmyadminInstallInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		result, err := installPHPMyAdmin(ctx, input, defaultPHPMyAdminEnvironment())
		return operationResult(result, err)
	case "phpmyadmin.activate":
		var input phpmyadminActivateInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		result, err := activatePHPMyAdmin(ctx, input, defaultPHPMyAdminEnvironment())
		return operationResult(result, err)
	case "phpmyadmin.disable":
		var input phpmyadminDisableInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, disablePHPMyAdmin(ctx, input, defaultPHPMyAdminEnvironment()))
	case "wordpress.ensure_cli":
		var input wordpressEnsureCLIInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, ensureWPCLI(ctx, input, defaultWordPressEnvironment()))
	case "wordpress.install":
		var input wordpressInstallInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, installWordPress(ctx, input, defaultWordPressEnvironment()))
	case "wordpress.update_core":
		var input wordpressUpdateInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, updateWordPress(ctx, input, defaultWordPressEnvironment()))
	case "wordpress.configure_cron":
		var input wordpressCronInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, configureWordPressCron(ctx, input, defaultWordPressEnvironment()))
	case "wordpress.clear_cache":
		var input siteInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, clearWordPressCache(ctx, input, siteRootPath))
	case "wordpress.update_db_config":
		var input wordpressDBConfigInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, updateWordPressDBConfig(ctx, input, siteRootPath))
	case "redis.ensure_site_acl":
		var input redisACLInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, ensureRedisACL(ctx, input, defaultRedisEnvironment()))
	case "redis.remove_site_acl":
		var input redisACLInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, removeRedisACL(ctx, input, defaultRedisEnvironment()))
	case "laravel.checkout":
		var input laravelCheckoutInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, checkoutLaravel(ctx, input, defaultLaravelEnvironment()))
	case "laravel.composer_install":
		var input laravelReleaseInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, composerInstallLaravel(ctx, input, defaultLaravelEnvironment()))
	case "laravel.node_build":
		var input laravelReleaseInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, nodeBuildLaravel(ctx, input, defaultLaravelEnvironment()))
	case "laravel.migrate":
		var input laravelReleaseInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, migrateLaravel(ctx, input, defaultLaravelEnvironment()))
	case "laravel.optimize":
		var input laravelReleaseInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, optimizeLaravel(ctx, input, defaultLaravelEnvironment()))
	case "laravel.health_check":
		var input laravelHealthInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, healthCheckLaravel(ctx, input, defaultLaravelEnvironment()))
	case "laravel.activate_release":
		var input laravelReleaseInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, activateLaravel(ctx, input, defaultLaravelEnvironment()))
	case "laravel.configure_environment":
		var input laravelEnvInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, configureLaravelEnvironment(ctx, input, defaultLaravelEnvironment()))
	case "laravel.ensure_deploy_key":
		var input laravelDeployKeyInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		result, err := ensureLaravelDeployKey(ctx, input, defaultLaravelEnvironment())
		return operationResult(result, err)
	case "laravel.ensure_workers":
		var input laravelWorkersInput
		if err := decodeStrict(request.Payload, &input); err != nil {
			return invalidPayload(request.Operation)
		}
		return operationResult(struct{}{}, ensureLaravelWorkers(ctx, input, defaultLaravelEnvironment()))
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
