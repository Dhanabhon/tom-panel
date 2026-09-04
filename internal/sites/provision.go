package sites

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/agentapi"
	"github.com/Dhanabhon/tom-panel/internal/jobs"
	panelruntime "github.com/Dhanabhon/tom-panel/internal/runtime"
)

const (
	ProvisionJobKind  = "site.provision"
	SetEnabledJobKind = "site.set_enabled"
	agentTimeout      = 30 * time.Second
)

type nginxRenderer func(Site) ([]byte, error)
type provisionAgentCall func(context.Context, string, any, any) error

type provisionInput struct {
	Site      Site                    `json:"site"`
	PHPConfig *panelruntime.PHPConfig `json:"php_config,omitempty"`
}

type setEnabledInput struct {
	Site      Site                    `json:"site"`
	PHPConfig *panelruntime.PHPConfig `json:"php_config,omitempty"`
	Enabled   bool                    `json:"enabled"`
}

type Provisioner struct {
	repository *Repository
	runtime    *panelruntime.Service
	render     nginxRenderer
	agentCall  provisionAgentCall
}

func NewProvisioner(repository *Repository, runtimeService *panelruntime.Service, agent *agentapi.Client, render nginxRenderer) *Provisioner {
	call := provisionAgentCall(func(context.Context, string, any, any) error {
		return errors.New("privileged agent is unavailable")
	})
	if agent != nil {
		call = agent.Call
	}
	return &Provisioner{repository: repository, runtime: runtimeService, render: render, agentCall: call}
}

func (p *Provisioner) Register(manager *jobs.Manager) error {
	if p == nil || p.repository == nil || manager == nil {
		return errors.New("site provisioner dependencies are required")
	}
	if err := manager.Register(ProvisionJobKind, p.buildProvisionJob); err != nil {
		return err
	}
	return manager.Register(SetEnabledJobKind, p.buildSetEnabledJob)
}

func (p *Provisioner) BuildProvisionJob(siteID string) (jobs.Definition, error) {
	site, config, err := p.snapshot(siteID)
	if err != nil {
		return jobs.Definition{}, err
	}
	if site.State != StateProvisioning && site.State != StateFailed {
		return jobs.Definition{}, errors.New("site is not awaiting provisioning")
	}
	input, err := json.Marshal(provisionInput{Site: site, PHPConfig: config})
	if err != nil {
		return jobs.Definition{}, err
	}
	return p.buildProvisionJob(input)
}

func (p *Provisioner) BuildSetEnabledJob(siteID string, enabled bool) (jobs.Definition, error) {
	site, config, err := p.snapshot(siteID)
	if err != nil {
		return jobs.Definition{}, err
	}
	if enabled && site.State != StateDisabled || !enabled && site.State != StateActive {
		return jobs.Definition{}, errors.New("site state does not allow this operation")
	}
	input, err := json.Marshal(setEnabledInput{Site: site, PHPConfig: config, Enabled: enabled})
	if err != nil {
		return jobs.Definition{}, err
	}
	return p.buildSetEnabledJob(input)
}

func (p *Provisioner) snapshot(siteID string) (Site, *panelruntime.PHPConfig, error) {
	site, err := p.repository.Get(context.Background(), siteID)
	if err != nil {
		return Site{}, nil, err
	}
	if site.Kind != KindPHP {
		return site, nil, nil
	}
	if p.runtime == nil {
		return Site{}, nil, errors.New("PHP runtime service is unavailable")
	}
	config, err := p.runtime.Config(context.Background(), site.ID)
	if err != nil {
		return Site{}, nil, err
	}
	return site, &config, nil
}

func (p *Provisioner) buildProvisionJob(raw json.RawMessage) (jobs.Definition, error) {
	var input provisionInput
	if err := decodeProvisionInput(raw, &input); err != nil {
		return jobs.Definition{}, err
	}
	if err := validateSnapshot(input.Site, input.PHPConfig); err != nil {
		return jobs.Definition{}, err
	}
	steps := []jobs.Step{
		p.provisionAgentStep("site.identity", input.Site.ID, "site.ensure_identity", siteAgentInput{SiteID: input.Site.ID}),
		p.provisionAgentStep("site.directories", input.Site.ID, "site.ensure_directories", siteAgentInput{SiteID: input.Site.ID}),
	}
	if input.PHPConfig != nil {
		pool, err := panelruntime.RenderPool(input.Site.ID, *input.PHPConfig)
		if err != nil {
			return jobs.Definition{}, err
		}
		phpInput := phpAgentInput{SiteID: input.Site.ID, Version: input.PHPConfig.Version, Config: string(pool)}
		steps = append(steps,
			p.provisionAgentStep("php.ensure", input.Site.ID, "php.ensure_pool", phpInput),
			p.provisionAgentStep("php.activate", input.Site.ID, "php.activate_pool", phpInput),
		)
	}
	nginx, err := p.renderNginx(input.Site)
	if err != nil {
		return jobs.Definition{}, err
	}
	steps = append(steps,
		p.provisionAgentStep("nginx.activate", input.Site.ID, "nginx.validate_activate", nginxAgentInput{
			SiteID: input.Site.ID, Config: string(nginx), HealthHost: input.Site.PrimaryDomain, HealthPort: input.Site.HTTPPort,
		}),
		p.stateStep("site.active", input.Site.ID, StateActive, true),
	)
	return jobs.Definition{Kind: ProvisionJobKind, Input: append(json.RawMessage(nil), raw...), Steps: steps}, nil
}

func (p *Provisioner) buildSetEnabledJob(raw json.RawMessage) (jobs.Definition, error) {
	var input setEnabledInput
	if err := decodeProvisionInput(raw, &input); err != nil {
		return jobs.Definition{}, err
	}
	if err := validateSnapshot(input.Site, input.PHPConfig); err != nil {
		return jobs.Definition{}, err
	}
	var steps []jobs.Step
	if !input.Enabled {
		steps = []jobs.Step{
			p.agentStep("nginx.disable", "nginx.disable", siteAgentInput{SiteID: input.Site.ID}),
			p.stateStep("site.disabled", input.Site.ID, StateDisabled, false),
		}
	} else {
		if input.PHPConfig != nil {
			pool, err := panelruntime.RenderPool(input.Site.ID, *input.PHPConfig)
			if err != nil {
				return jobs.Definition{}, err
			}
			steps = append(steps, p.agentStep("php.activate", "php.activate_pool", phpAgentInput{
				SiteID: input.Site.ID, Version: input.PHPConfig.Version, Config: string(pool),
			}))
		}
		nginx, err := p.renderNginx(input.Site)
		if err != nil {
			return jobs.Definition{}, err
		}
		steps = append(steps,
			p.agentStep("nginx.activate", "nginx.validate_activate", nginxAgentInput{
				SiteID: input.Site.ID, Config: string(nginx), HealthHost: input.Site.PrimaryDomain, HealthPort: input.Site.HTTPPort,
			}),
			p.stateStep("site.active", input.Site.ID, StateActive, false),
		)
	}
	return jobs.Definition{Kind: SetEnabledJobKind, Input: append(json.RawMessage(nil), raw...), Steps: steps}, nil
}

func (p *Provisioner) renderNginx(site Site) ([]byte, error) {
	if p.render == nil {
		return nil, errors.New("Nginx renderer is unavailable")
	}
	return p.render(site)
}

func (p *Provisioner) provisionAgentStep(key, siteID, operation string, input any) jobs.Step {
	step := p.agentStep(key, operation, input)
	run := step.Run
	step.Run = func(ctx context.Context) (json.RawMessage, error) {
		if err := p.prepareProvisionRetry(ctx, siteID); err != nil {
			return nil, err
		}
		result, err := run(ctx)
		if err != nil {
			_ = p.markProvisionFailed(ctx, siteID)
		}
		return result, err
	}
	return step
}

func (p *Provisioner) agentStep(key, operation string, input any) jobs.Step {
	return jobs.Step{Key: key, Reconcile: retrySafe, Run: func(ctx context.Context) (json.RawMessage, error) {
		ctx, cancel := context.WithTimeout(ctx, agentTimeout)
		defer cancel()
		var result json.RawMessage
		if err := p.agentCall(ctx, operation, input, &result); err != nil {
			return nil, err
		}
		if len(result) == 0 {
			result = json.RawMessage(`{}`)
		}
		return result, nil
	}}
}

func (p *Provisioner) stateStep(key, siteID string, next State, provision bool) jobs.Step {
	return jobs.Step{Key: key, Reconcile: retrySafe, Run: func(ctx context.Context) (json.RawMessage, error) {
		if provision {
			if err := p.prepareProvisionRetry(ctx, siteID); err != nil {
				return nil, err
			}
		}
		if err := p.repository.SetState(ctx, siteID, next); err != nil {
			return nil, err
		}
		return json.RawMessage(`{"state":"` + next + `"}`), nil
	}}
}

func (p *Provisioner) prepareProvisionRetry(ctx context.Context, siteID string) error {
	site, err := p.repository.Get(ctx, siteID)
	if err != nil {
		return err
	}
	if site.State == StateFailed {
		return p.repository.SetState(ctx, siteID, StateProvisioning)
	}
	if site.State != StateProvisioning && site.State != StateActive {
		return errors.New("site provisioning state is incompatible")
	}
	return nil
}

func (p *Provisioner) markProvisionFailed(ctx context.Context, siteID string) error {
	site, err := p.repository.Get(ctx, siteID)
	if err != nil || site.State != StateProvisioning {
		return err
	}
	return p.repository.SetState(ctx, siteID, StateFailed)
}

func retrySafe(context.Context) (jobs.Reconciliation, error) {
	return jobs.Reconciliation{Outcome: jobs.ReconcileRetry}, nil
}

func validateSnapshot(site Site, config *panelruntime.PHPConfig) error {
	if err := ValidateCreate(CreateInput{
		Kind: site.Kind, PrimaryDomain: site.PrimaryDomain, HTTPPort: site.HTTPPort, HTTPSPort: site.HTTPSPort,
		Public: site.Public, PHPVersion: site.PHPVersion, ProxyTarget: site.ProxyTarget,
	}, nil); err != nil {
		return err
	}
	if len(site.ID) != 32 {
		return ErrInvalidSite
	}
	if site.Kind == KindPHP {
		if config == nil || config.Version != site.PHPVersion {
			return errors.New("PHP runtime snapshot does not match site")
		}
		return panelruntime.ValidatePHPConfig(*config)
	}
	if config != nil {
		return errors.New("non-PHP site has a PHP runtime snapshot")
	}
	return nil
}

func decodeProvisionInput(raw json.RawMessage, output any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode site job input: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("site job input contains trailing data")
	}
	return nil
}

type siteAgentInput struct {
	SiteID string `json:"site_id"`
}

type phpAgentInput struct {
	SiteID  string `json:"site_id"`
	Version string `json:"version"`
	Config  string `json:"config"`
}

type nginxAgentInput struct {
	SiteID     string `json:"site_id"`
	Config     string `json:"config"`
	HealthHost string `json:"health_host"`
	HealthPort int    `json:"health_port"`
}
