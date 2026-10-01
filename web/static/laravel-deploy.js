// Laravel deployment progressive enhancement: explicit confirmation dialog
// before submitting the fixed pipeline. Without JavaScript the form's own
// required checkbox still gates the request.
(function () {
  "use strict";

  var form = document.querySelector("[data-deploy-form]");
  if (!form) {
    return;
  }
  form.addEventListener("submit", function (event) {
    var migrations = form.querySelector('input[name="run_migrations"]');
    var message = "Deploy a new release now?";
    if (migrations && migrations.checked) {
      message += "\n\nDatabase migrations will run as part of this deployment.";
    }
    if (!window.confirm(message)) {
      event.preventDefault();
    }
  });
})();
