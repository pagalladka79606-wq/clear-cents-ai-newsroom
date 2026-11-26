

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === "/api/health") {
      return Response.json({
        status: "success",
        project: "Clear Cents AI Newsroom",
        message: "Newsroom backend is running",
        date: new Date().toISOString()
      });
    }

    // WordPress connection test
    if (url.pathname === "/api/wordpress-test") {
      if (request.method !== "GET") {
        return Response.json(
          { status: "error", message: "Method not allowed" },
          { status: 405 }
        );
      }

      const site = env.WP_SITE_URL;
      const username = env.WP_USERNAME;
      const password = env.WP_APP_PASSWORD;

      if (!site || !username || !password) {
        return Response.json({
          status: "error",
          message: "WordPress secrets are missing"
        }, { status: 500 });
      }

      try {
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
          return Response.json({
            status: "error",
            message: "WordPress authentication failed",
            wordpress_status: response.status
          }, { status: 502 });
        }

        const user = await response.json();

        return Response.json({
          status: "success",
          project: "Clear Cents AI Newsroom",
          wordpress_connected: true,
          message: "WordPress authentication successful",
          authenticated_user: user.name
        });

      } catch (error) {
        return Response.json({
          status: "error",
          message: "Could not connect to WordPress"
        }, { status: 502 });
      }
    }

    // Serve website assets
    return env.ASSETS.fetch(request);
  }
};
