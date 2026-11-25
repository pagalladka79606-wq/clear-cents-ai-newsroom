
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

    // Serve website assets
    return env.ASSETS.fetch(request);
  }
};
