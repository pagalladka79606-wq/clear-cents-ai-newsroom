
const SESSION_TTL = 1800;
const COOKIE_NAME = "__Host-NEWSROOM_SESSION";
const HASH_ITERATIONS = 600000;
const encoder = new TextEncoder();

function json(data, status = 200, extraHeaders = {}) {
  const headers = new Headers({
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    ...extraHeaders
  });

  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}

function constantTimeEqual(a, b) {
  const aa = encoder.encode(String(a));
  const bb = encoder.encode(String(b));

  let difference = aa.length ^ bb.length;
  const length = Math.max(aa.length, bb.length);

  for (let i = 0; i < length; i++) {
    difference |= (aa[i] || 0) ^ (bb[i] || 0);
  }

  return difference === 0;
}

function base64UrlDecode(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Invalid encoding");
  }

  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);

  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

function base64UrlEncode(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );

  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

async function verifyPassword(password, storedHash) {
  try {
    const parts = storedHash.split("$");

    if (
      parts.length !== 4 ||
      parts[0] !== "pbkdf2-sha256" ||
      parts[1] !== String(HASH_ITERATIONS)
    ) {
      return false;
    }

    const salt = base64UrlDecode(parts[2]);
    const expected = base64UrlDecode(parts[3]);

    if (salt.length !== 16 || expected.length !== 32) {
      return false;
    }

    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const result = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations: HASH_ITERATIONS
      },
      key,
      256
    );

    return constantTimeEqual(
      base64UrlEncode(new Uint8Array(result)),
      parts[3]
    );
  } catch {
    return false;
  }
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";

  for (const item of cookieHeader.split(";")) {
    const part = item.trim();
    const separator = part.indexOf("=");

    if (separator < 0) continue;

    if (part.slice(0, separator) === name) {
      return part.slice(separator + 1);
    }
  }

  return null;
}

function sessionCookie(token) {
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL}`;
}

function expiredCookie() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

function validOrigin(request) {
  const origin = request.headers.get("Origin");

  if (!origin) return false;

  try {
    return origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

function newSessionToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return base64UrlEncode(bytes);
}

async function getAdminSession(request, env) {
  if (!env.NEWSROOM_SESSIONS) {
    return { error: "Session storage is not configured" };
  }

  const token = getCookie(request, COOKIE_NAME);

  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) {
    return { session: null };
  }

  const key = "session:" + await sha256Hex(token);

  try {
    const stored = await env.NEWSROOM_SESSIONS.get(key);

    if (!stored) {
      return { session: null };
    }

    const session = JSON.parse(stored);

    if (
      !Number.isFinite(session.expiresAt) ||
      session.expiresAt <= Date.now()
    ) {
      await env.NEWSROOM_SESSIONS.delete(key);
      return { session: null };
    }

    return { session, key };
  } catch {
    return { error: "Session storage unavailable" };
  }
}

async function requireAdmin(request, env) {
  const result = await getAdminSession(request, env);

  if (result.error) {
    return {
      ok: false,
      response: json({
        status: "error",
        message: result.error
      }, 503)
    };
  }

  if (!result.session) {
    return {
      ok: false,
      response: json({
        status: "error",
        message: "Authentication required"
      }, 401)
    };
  }

  return {
    ok: true,
    session: result.session
  };
}

async function login(request, env) {
  if (request.method !== "POST") {
    return json({ message: "Method not allowed" }, 405, {
      Allow: "POST"
    });
  }

  if (!validOrigin(request)) {
    return json({ message: "Invalid request origin" }, 403);
  }

  if (
    !env.NEWSROOM_ADMIN_USERNAME ||
    !env.NEWSROOM_ADMIN_PASSWORD_HASH ||
    !env.NEWSROOM_SESSIONS ||
    !env.NEWSROOM_LOGIN_LIMITER
  ) {
    return json({
      status: "error",
      message: "Authentication configuration incomplete"
    }, 503);
  }

  const ip = request.headers.get("CF-Connecting-IP") || "unknown";

  try {
    const limit = await env.NEWSROOM_LOGIN_LIMITER.limit({
      key: ip
    });

    if (!limit.success) {
      return json({
        status: "error",
        message: "Too many login attempts. Try again later."
      }, 429, {
        "Retry-After": "60"
      });
    }
  } catch {
    return json({
      status: "error",
      message: "Login protection temporarily unavailable"
    }, 503);
  }

  if (
    !(request.headers.get("Content-Type") || "")
      .toLowerCase()
      .includes("application/json")
  ) {
    return json({ message: "JSON required" }, 415);
  }

  let body;

  try {
    const raw = await request.text();

    if (raw.length > 4096) {
      return json({ message: "Request too large" }, 413);
    }

    body = JSON.parse(raw);
  } catch {
    return json({ message: "Invalid request" }, 400);
  }

  const username = body?.username;
  const password = body?.password;

  if (
    typeof username !== "string" ||
    typeof password !== "string" ||
    username.length > 128 ||
    password.length < 20 ||
    password.length > 1024
  ) {
    return json({
      status: "error",
      message: "Invalid username or password"
    }, 401);
  }

  const usernameValid = constantTimeEqual(
    username,
    env.NEWSROOM_ADMIN_USERNAME
  );

  const passwordValid = await verifyPassword(
    password,
    env.NEWSROOM_ADMIN_PASSWORD_HASH
  );

  if (!usernameValid || !passwordValid) {
    return json({
      status: "error",
      message: "Invalid username or password"
    }, 401);
  }

  const token = newSessionToken();
  const key = "session:" + await sha256Hex(token);

  const session = {
    username: env.NEWSROOM_ADMIN_USERNAME,
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_TTL * 1000
  };

  try {
    await env.NEWSROOM_SESSIONS.put(
      key,
      JSON.stringify(session),
      { expirationTtl: SESSION_TTL }
    );
  } catch {
    return json({
      status: "error",
      message: "Could not create session"
    }, 503);
  }

  return json({
    status: "success",
    authenticated: true,
    expires_in: SESSION_TTL
  }, 200, {
    "Set-Cookie": sessionCookie(token)
  });
}

async function logout(request, env) {
  if (request.method !== "POST") {
    return json({ message: "Method not allowed" }, 405, {
      Allow: "POST"
    });
  }

  if (!validOrigin(request)) {
    return json({ message: "Invalid request origin" }, 403);
  }

  const result = await getAdminSession(request, env);

  if (result.error) {
    return json({ message: result.error }, 503);
  }

  if (result.key) {
    try {
      await env.NEWSROOM_SESSIONS.delete(result.key);
    } catch {
      return json({
        status: "error",
        message: "Could not revoke session. Please retry."
      }, 503);
    }
  }

  return json({
    status: "success",
    authenticated: false,
    message: "Logged out"
  }, 200, {
    "Set-Cookie": expiredCookie()
  });
}

async function testWordPress(env) {
  const site = env.WP_SITE_URL;
  const username = env.WP_USERNAME;
  const password = env.WP_APP_PASSWORD;

  if (!site || !username || !password) {
    return json({
      status: "error",
      message: "WordPress credentials are missing"
    }, 500);
  }

  try {
    const parsedUrl = new URL(site);

    if (
      parsedUrl.protocol !== "https:" ||
      parsedUrl.username ||
      parsedUrl.password
    ) {
      return json({
        status: "error",
        message: "WordPress must use a valid HTTPS URL"
      }, 400);
    }

    const base = site.replace(/\/+$/, "");

    const response = await fetch(
      `${base}/wp-json/wp/v2/users/me?context=edit`,
      {
        headers: {
          Authorization: "Basic " + btoa(
            `${username}:${password.replace(/\s/g, "")}`
          ),
          Accept: "application/json"
        },
        signal: AbortSignal.timeout(10000)
      }
    );

    if (!response.ok) {
      return json({
        status: "error",
        message: "WordPress authentication failed",
        wordpress_status: response.status
      }, 502);
    }

    const user = await response.json();

    return json({
      status: "success",
      project: "Clear Cents AI Newsroom",
      wordpress_connected: true,
      message: "WordPress authentication successful",
      authenticated_user: user.name
    });
  } catch {
    return json({
      status: "error",
      message: "Could not connect to WordPress"
    }, 502);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/api/health") {
      if (request.method !== "GET") {
        return json({ message: "Method not allowed" }, 405);
      }

      return json({
        status: "success",
        project: "Clear Cents AI Newsroom",
        message: "Newsroom backend is running",
        automation: "Not yet activated",
        date: new Date().toISOString()
      });
    }

    if (path === "/api/login") {
      return login(request, env);
    }

    if (path === "/api/logout") {
      return logout(request, env);
    }

    if (path === "/api/session") {
      if (request.method !== "GET") {
        return json({ message: "Method not allowed" }, 405);
      }

      const result = await getAdminSession(request, env);

      if (result.error) {
        return json({ message: result.error }, 503);
      }

      return json({
        status: "success",
        authenticated: Boolean(result.session),
        username: result.session?.username || null,
        expires_at: result.session?.expiresAt || null
      });
    }

    if (path.startsWith("/api/")) {
      if (request.method !== "GET" && !validOrigin(request)) {
        return json({ message: "Invalid request origin" }, 403);
      }

      const auth = await requireAdmin(request, env);

      if (!auth.ok) {
        return auth.response;
      }

      if (path === "/api/wordpress-test") {
        if (request.method !== "GET") {
          return json({ message: "Method not allowed" }, 405, {
            Allow: "GET"
          });
        }

        return testWordPress(env);
      }

      return json({
        status: "error",
        message: "API endpoint not found"
      }, 404);
    }

    if (!env.ASSETS) {
      return new Response("Assets binding unavailable", {
        status: 503
      });
    }

    return env.ASSETS.fetch(request);
  },

  async scheduled(controller, env, ctx) {
    console.log(
      "Clear Cents AI Newsroom: Cron event received."
    );

    console.log(
      "Automation remains safely paused until the complete research, evidence, quota and drafting pipeline is implemented."
    );
  }
};

