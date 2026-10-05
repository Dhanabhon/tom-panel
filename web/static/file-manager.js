// File Manager progressive enhancement: confirmation dialogs, inline rename
// and copy prompts, and upload feedback. The page remains functional without
// JavaScript because every action is a plain form submission.
(function () {
  "use strict";

  var browser = document.querySelector("[data-file-browser]");
  if (!browser) {
    return;
  }
  var csrf = document.querySelector('input[name="csrf_token"]');
  var token = csrf ? csrf.value : "";
  var sitePath = browser.getAttribute("data-path") || ".";

  function post(action, fields) {
    var form = document.createElement("form");
    form.method = "post";
    form.action = action;
    var payload = Object.assign({ csrf_token: token, path: sitePath }, fields);
    Object.keys(payload).forEach(function (name) {
      if (payload[name] === undefined || payload[name] === null) {
        return;
      }
      var input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      input.value = payload[name];
      form.appendChild(input);
    });
    document.body.appendChild(form);
    form.submit();
  }

  function promptName(label, current) {
    var value = window.prompt(label, current);
    if (!value || value === current) {
      return null;
    }
    return value.trim();
  }

  browser.addEventListener("click", function (event) {
    var target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }
    var base = "/sites/" + window.location.pathname.split("/")[2];
    var name;
    if (target.hasAttribute("data-trash")) {
      name = target.getAttribute("data-trash");
      if (window.confirm('Move "' + name + '" to trash?')) {
        post(base + "/files/trash", { path: joinPath(name) });
      }
    } else if (target.hasAttribute("data-rename")) {
      name = target.getAttribute("data-rename");
      var renamed = promptName('Rename "' + name + '" to', name);
      if (renamed) {
        post(base + "/files/rename", { path: joinPath(name), name: renamed });
      }
    } else if (target.hasAttribute("data-copy")) {
      name = target.getAttribute("data-copy");
      var copyName = promptName('Copy "' + name + '" to', name.replace(/(\.[^.]*)?$/, function (part) {
        return "-copy" + (part || "");
      }));
      if (copyName) {
        post(base + "/files/copy", { path: joinPath(name), name: copyName });
      }
    }
  });

  function joinPath(name) {
    return sitePath === "." ? name : sitePath.replace(/^\/+|\/+$/g, "") + "/" + name;
  }

  var upload = document.querySelector("[data-upload-input]");
  if (upload && upload.form) {
    upload.form.addEventListener("submit", function () {
      var button = upload.form.querySelector("button[type=submit]");
      if (button) {
        button.disabled = true;
        button.textContent = "Uploading…";
      }
    });
  }

  var oneTime = document.querySelector("[data-one-time-password]");
  if (oneTime) {
    var range = document.createRange();
    range.selectNodeContents(oneTime);
    var selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
  }
})();
