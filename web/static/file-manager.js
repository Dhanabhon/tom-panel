// File Manager progressive enhancement: confirmation dialogs, inline rename
// and copy editing, and upload feedback. The page remains functional without
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

  function joinPath(name) {
    return sitePath === "." ? name : sitePath.replace(/^\/+|\/+$/g, "") + "/" + name;
  }

  // inlineEdit swaps a table cell for a text input with save/cancel. The
  // cell's original markup is restored on cancel so nothing is lost.
  function inlineEdit(cell, suggested, onSubmit) {
    var original = cell.innerHTML;
    while (cell.firstChild) {
      cell.removeChild(cell.firstChild);
    }
    var input = document.createElement("input");
    input.type = "text";
    input.className = "mono";
    input.value = suggested;
    input.setAttribute("aria-label", "New name");
    var save = document.createElement("button");
    save.type = "button";
    save.className = "link";
    save.textContent = "Save";
    var cancel = document.createElement("button");
    cancel.type = "button";
    cancel.className = "link danger";
    cancel.textContent = "Cancel";
    cell.appendChild(input);
    cell.appendChild(save);
    cell.appendChild(cancel);
    input.focus();
    input.select();

    function restore() {
      cell.innerHTML = original;
    }
    function submit() {
      var value = input.value.trim();
      if (!value || value === suggested) {
        restore();
        return;
      }
      onSubmit(value);
    }
    save.addEventListener("click", submit);
    cancel.addEventListener("click", restore);
    input.addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        event.preventDefault();
        submit();
      } else if (event.key === "Escape") {
        restore();
      }
    });
  }

  function nameCell(row) {
    return row.cells[1] || null;
  }

  browser.addEventListener("click", function (event) {
    var target = event.target;
    if (!(target instanceof HTMLElement)) {
      return;
    }
    var base = "/sites/" + window.location.pathname.split("/")[2];
    var row = target.closest("tr");
    var cell = row ? nameCell(row) : null;
    if (target.hasAttribute("data-trash")) {
      var trashName = target.getAttribute("data-trash");
      if (window.confirm('Move "' + trashName + '" to trash?')) {
        post(base + "/files/trash", { path: joinPath(trashName) });
      }
    } else if (target.hasAttribute("data-rename") && cell) {
      var renameFrom = target.getAttribute("data-rename");
      inlineEdit(cell, renameFrom, function (renamed) {
        post(base + "/files/rename", { path: joinPath(renameFrom), name: renamed });
      });
    } else if (target.hasAttribute("data-copy") && cell) {
      var copyFrom = target.getAttribute("data-copy");
      var suggested = copyFrom.replace(/(\.[^.]*)?$/, function (part) {
        return "-copy" + (part || "");
      });
      inlineEdit(cell, suggested, function (copyName) {
        post(base + "/files/copy", { path: joinPath(copyFrom), name: copyName });
      });
    }
  });

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
