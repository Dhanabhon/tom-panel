(() => {
  const formBody = form => new URLSearchParams(new FormData(form));
  const showError = (form, visible = true) => {
    const error = form.querySelector("[data-form-error]");
    if (error) error.hidden = !visible;
  };

  // Destructive-action confirmation: capture phase so a decline stops every
  // later handler, on every page, regardless of which container binds click.
  document.addEventListener("click", event => {
    const target = event.target instanceof Element ? event.target.closest("[data-confirm]") : null;
    if (!target) return;
    if (!window.confirm(target.getAttribute("data-confirm"))) {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
  }, true);

  // Guard against double submits on plain POST forms. Fetch-driven forms
  // (login, setup, logout) call preventDefault first, so they are skipped
  // and manage their own button state.
  document.addEventListener("submit", event => {
    if (event.defaultPrevented) return;
    const submit = event.submitter ?? event.target.querySelector('button[type="submit"], button:not([type])');
    if (submit) submit.disabled = true;
  });

  document.querySelector("[data-nav-toggle]")?.addEventListener("click", event => {
    const content = document.querySelector("#main-nav");
    const open = content?.classList.toggle("open") ?? false;
    event.currentTarget.setAttribute("aria-expanded", String(open));
  });

  document.querySelector("[data-login-form]")?.addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const factor = form.querySelector("[data-factor]");
    const code = form.elements.code;
    const submit = form.querySelector("[data-login-submit]");
    showError(form, false);
    submit.disabled = true;
    try {
      if (!form.dataset.challenge) {
        const response = await fetch("/login", {method: "POST", body: formBody(form)});
        if (!response.ok) throw new Error("login failed");
        const payload = await response.json();
        form.dataset.challenge = payload.challenge;
        form.elements.password.value = "";
        form.querySelectorAll("[data-credentials] input").forEach(input => { input.disabled = true; });
        factor.hidden = false;
        code.disabled = false;
        code.focus();
        submit.textContent = "Sign in securely";
      } else {
        const body = new URLSearchParams({challenge: form.dataset.challenge, code: code.value});
        const response = await fetch("/login/totp", {method: "POST", body});
        code.value = "";
        if (!response.ok) throw new Error("factor failed");
        location.assign("/");
      }
    } catch (_) {
      showError(form);
    } finally {
      submit.disabled = false;
    }
  });

  document.querySelector("[data-use-recovery]")?.addEventListener("click", event => {
    const input = event.currentTarget.form.elements.code;
    input.inputMode = "text";
    input.placeholder = "Recovery code";
    input.focus();
  });

  const setupForm = document.querySelector("[data-setup-form]");
  if (setupForm) {
    const token = new URLSearchParams(location.hash.slice(1)).get("token");
    history.replaceState({}, "", `${location.pathname}${location.search}`);
    if (token) {
      setupForm.elements.setup_token.value = token;
      setupForm.hidden = false;
    } else {
      setupForm.hidden = true;
      document.querySelector("[data-setup-missing]").hidden = false;
    }
  }

  setupForm?.addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    showError(form, false);
    const submit = form.querySelector("button[type=submit]");
    submit.disabled = true;
    try {
      const response = await fetch("/setup", {method: "POST", body: formBody(form)});
      form.elements.password.value = "";
      if (!response.ok) throw new Error("setup failed");
      const enrollment = await response.json();
      const panel = document.querySelector("[data-enrollment]");
      panel.querySelector("[data-totp-secret]").textContent = enrollment.totp_secret;
      panel.querySelector("[data-totp-uri]").textContent = enrollment.totp_uri;
      panel.querySelector("[data-recovery-codes]").textContent = enrollment.recovery_codes.join("\n");
      form.remove();
      panel.hidden = false;
      history.replaceState({}, "", "/login");
    } catch (_) {
      showError(form);
      submit.disabled = false;
    }
  });

  document.querySelector("[data-logout]")?.addEventListener("submit", async event => {
    event.preventDefault();
    const response = await fetch("/logout", {method: "POST", body: formBody(event.currentTarget)});
    if (response.ok) location.assign("/login");
  });

  const terminal = new Set(["succeeded", "failed", "cancelled"]);
  const label = status => status.charAt(0).toUpperCase() + status.slice(1);
  document.querySelectorAll("[data-job-id]").forEach(row => {
    if (terminal.has(row.dataset.jobStatus)) return;
    const state = row.querySelector("[data-connection-state]");
    const stream = new EventSource(`/jobs/${row.dataset.jobId}/events`);
    state.textContent = "Connecting";
    stream.addEventListener("open", () => { state.textContent = "Live"; });
    stream.addEventListener("error", () => { state.textContent = "Reconnecting"; });
    stream.addEventListener("job", event => {
      const update = JSON.parse(event.data);
      if (update.revision <= Number(row.dataset.jobRevision)) return;
      row.dataset.jobRevision = String(update.revision);
      row.dataset.jobStatus = update.status;
      const badge = row.querySelector("[data-job-status-label]");
      badge.textContent = label(update.status);
      badge.className = `badge ${update.status === "succeeded" ? "good" : terminal.has(update.status) ? "bad" : "warn"}`;
      const error = row.querySelector("[data-job-error]");
      if (update.error) { error.textContent = update.error; error.hidden = false; }
      if (update.step_key) {
        const step = Array.from(row.querySelectorAll("[data-step-key]")).find(item => item.dataset.stepKey === update.step_key);
        if (step) step.querySelector("[data-step-status]").textContent = update.step_status;
      }
      if (terminal.has(update.status)) { state.textContent = "Persisted"; stream.close(); }
    });
  });
})();
