const SSO_BASE = window.SSO_BASE || "http://localhost:8520";

function el(tag, attrs = {}, text = "") {
  const node = document.createElement(tag);
  Object.entries(attrs).forEach(([k, v]) => (node[k] = v));
  if (text) node.textContent = text;
  return node;
}

function iconButton(label, iconSrc) {
  const btn = el("button", { className: "sso-btn", type: "button" });
  if (iconSrc) {
    const img = el("img", { className: "sso-icon", src: iconSrc, alt: "" });
    btn.appendChild(img);
  }
  btn.appendChild(document.createTextNode(label));
  return btn;
}

async function api(path) {
  const res = await fetch(`${SSO_BASE}${path}`, { credentials: "include" });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(data?.detail || `HTTP ${res.status}`);
  return data;
}

async function post(path, body) {
  const res = await fetch(`${SSO_BASE}${path}`,
    {
      method: "POST",
      credentials: "include",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }
  );
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(data?.detail || `HTTP ${res.status}`);
  return data;
}

async function buildActions(email) {
  const actions = document.getElementById("actions");
  actions.innerHTML = "";

  const method = await api(`/api/v1/auth/method?email=${encodeURIComponent(email)}`);
  const domain = method.domain;

  if (method.methods.includes("google")) {
    const btn = iconButton("Sign in with Google", "./assets/google.svg");
    btn.onclick = () => {
      window.location.href = `${SSO_BASE}/api/v1/oauth/google/start?email=${encodeURIComponent(email)}&return_to=${encodeURIComponent(window.location.href)}`;
    };
    actions.appendChild(btn);
  }

  if (domain === "innogen-pharma.ph") {
    const exists = await api(`/api/v1/cpanel/mailbox-exists?email=${encodeURIComponent(email)}`);
    if (!exists.exists) {
      actions.appendChild(el("div", {}, "Mailbox does not exist in cPanel."));
      return;
    }

    const status = await api(`/api/v1/auth/password/status?email=${encodeURIComponent(email)}`);
    if (!status.has_password) {
      const pw = el("input", { type: "password", placeholder: "Create app password" });
      const btn = el("button", {}, "Create App Password");
      btn.onclick = async () => {
        await post("/api/v1/auth/password/create", { email, password: pw.value });
        actions.appendChild(el("div", {}, "Created. Session cookie set."));
      };
      actions.appendChild(pw);
      actions.appendChild(btn);
    } else {
      const pw = el("input", { type: "password", placeholder: "Password" });
      const btn = el("button", {}, "Password Login");
      btn.onclick = async () => {
        await post("/api/v1/auth/password/login", { email, password: pw.value });
        actions.appendChild(el("div", {}, "Logged in. Session cookie set."));
      };
      actions.appendChild(pw);
      actions.appendChild(btn);
    }
  }

  const appleBtn = iconButton("Sign in with Apple", "./assets/apple.svg");
  appleBtn.onclick = () => {
    const q = email ? `email=${encodeURIComponent(email)}&` : "";
    window.location.href = `${SSO_BASE}/api/v1/oauth/apple/start?${q}return_to=${encodeURIComponent(window.location.href)}`;
  };
  actions.appendChild(appleBtn);
}

document.getElementById("continue").onclick = async () => {
  const email = document.getElementById("email").value.trim();
  await buildActions(email);
};

document.getElementById("check").onclick = async () => {
  const out = await api("/api/v1/verify-session");
  document.getElementById("session").textContent = JSON.stringify(out, null, 2);
};

