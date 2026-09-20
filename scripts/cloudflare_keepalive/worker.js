/**
 * VAJRA Cloudflare Keep-Alive Worker
 * 
 * Schedule: Runs every 10 minutes via Cron Trigger ('* /10 * * * *')
 * Purpose: Pings Render free tier service so it NEVER spins down or goes to sleep.
 * Cost: $0.00 (100% free on Cloudflare Workers Free plan - up to 100,000 requests/day).
 * 
 * Deployment Instructions:
 * 1. Log in to your free Cloudflare dashboard: https://dash.cloudflare.com/
 * 2. Navigate to "Workers & Pages" -> "Create application" -> "Create Worker".
 * 3. Paste this code into the editor and click "Save and Deploy".
 * 4. Go to Worker "Settings" -> "Triggers" -> "Cron Triggers" -> "Add Cron Trigger".
 * 5. Set Cron syntax to: */10 * * * *
 * 6. Save! Render will now stay awake 24/7 with zero cold starts.
 */

const TARGET_SERVICES = [
  "https://vajra-7aue.onrender.com/health",
  "https://aravkataria-vajra.hf.space/health"
];

export default {
  // 1. Scheduled Cron execution (Every 10 minutes)
  async scheduled(event, env, ctx) {
    console.log(`[VAJRA Keep-Alive] Scheduled ping triggered at ${new Date().toISOString()}`);
    
    const fetchPromises = TARGET_SERVICES.map(async (url) => {
      try {
        const res = await fetch(url, {
          method: "GET",
          headers: {
            "User-Agent": "VAJRA-Cloudflare-KeepAlive/1.0"
          },
          signal: AbortSignal.timeout(10000)
        });
        console.log(`[VAJRA Keep-Alive] Pinged ${url} -> Status ${res.status}`);
        return { url, status: res.status, ok: res.ok };
      } catch (err) {
        console.warn(`[VAJRA Keep-Alive] Failed to ping ${url}: ${err.message}`);
        return { url, error: err.message };
      }
    });

    ctx.waitUntil(Promise.all(fetchPromises));
  },

  // 2. HTTP handler for manual testing in browser
  async fetch(request, env, ctx) {
    const results = [];
    for (const url of TARGET_SERVICES) {
      try {
        const res = await fetch(url, {
          headers: { "User-Agent": "VAJRA-Cloudflare-KeepAlive/1.0" }
        });
        results.push({ url, status: res.status, ok: res.ok });
      } catch (e) {
        results.push({ url, error: e.message });
      }
    }

    return new Response(JSON.stringify({
      service: "VAJRA-Cloudflare-KeepAlive",
      timestamp: new Date().toISOString(),
      results
    }, null, 2), {
      headers: { "Content-Type": "application/json" }
    });
  }
};
