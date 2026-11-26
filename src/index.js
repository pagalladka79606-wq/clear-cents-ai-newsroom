
function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store"
    }
  });
}

function constantTimeEqual(a, b) {
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);

  for (let i = 0; i < length; i++) {
    difference |=
      (a.charCodeAt(i) || 0) ^
      (b.charCodeAt(i) || 0);
  }

  return difference === 0;
}

function isAdmin(request, env) {
  const token = env.NEWSROOM_ADMIN_TOKEN;

  if (!token) {
    return "not_configured";
  }

  const authorization =
    request.headers.get("Authorization") || "";

  return constantTimeEqual(
    authorization,
    `Bearer ${token}`
  );
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

    if (parsedUrl.protocol !== "https:") {
      return json({
        status: "error",
        message: "WordPress must use HTTPS"
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
        }
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

    if (url.pathname === "/api/health") {
      return json({
        status: "success",
        project: "Clear Cents AI Newsroom",
        message: "Newsroom backend is running",
        automation: "Not yet activated",
        date: new Date().toISOString()
      });
    }

    if (url.pathname.startsWith("/api/")) {
      if (url.pathname === "/api/wordpress-test") {
        if (request.method !== "GET") {
          return json({
            status: "error",
            message: "Method not allowed"
          }, 405);
        }

        const auth = isAdmin(request, env);

        if (auth === "not_configured") {
          return json({
            status: "error",
            message: "Admin authentication is not configured"
          }, 503);
        }

        if (!auth) {
          return json({
            status: "error",
            message: "Unauthorized"
          }, 401);
        }

        return testWordPress(env);
      }

      return json({
        status: "error",
        message: "API endpoint not found"
      }, 404);
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
