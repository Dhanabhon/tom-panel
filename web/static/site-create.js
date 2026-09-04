(() => {
  const form = document.querySelector('[data-site-create]');
  if (!form) return;
  const kind = form.querySelector('[data-site-kind]');
  const update = () => {
    form.querySelectorAll('[data-kind-only]').forEach((section) => {
      const active = section.dataset.kindOnly === kind.value;
      section.hidden = !active;
      section.querySelectorAll('input, select').forEach((control) => { control.disabled = !active; });
    });
  };
  kind.addEventListener('change', update);
  update();
})();
