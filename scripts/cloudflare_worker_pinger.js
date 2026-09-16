/**
 * VAJRA 24/7 Dual Keep-Alive Cloudflare Worker
 * 
 * Pings both the Render FastAPI Backend and the Hugging Face Spaces
 * fine-tuned model container every 10 minutes on a Cloudflare Cron Trigger (*/10 * * * *).
 * 
 * - Render: Keeps the AST scanner and security API awake.
 * - Hugging Face: Keeps the fine-tuned model container warm without consuming ZeroGPU quota.
 * - 100% Free, Zero Credit Card, runs on Cloudflare Edge 24/7.
 */

export default {
  async scheduled(event, env, ctx) {
    const TARGETS = [
      "https://vajra-7aue.onrender.com/health",
      "https://aravkataria-vajra.hf.space"
    ];

    const results = await Promise.allSettled(
      TARGETS.map(async (url) => {
        const resp = await fetch(url, {
          headers: {
            "User-Agent": "VAJRA-Cloudflare-Pinger/2.0"
          }
        });
        return { url, status: resp.status };
      })
    );

    for (const r of results) {
      if (r.status === "fulfilled") {
        console.log(`[Pinger] OK: ${r.value.url} -> ${r.value.status}`);
      } else {
        console.error(`[Pinger] FAIL: ${r.reason}`);
      }
    }
  },

  async fetch(request, env, ctx) {
    return new Response(
      JSON.stringify({
        service: "VAJRA 24/7 Keep-Alive Worker",
        status: "ACTIVE",
        targets: [
          "https://vajra-7aue.onrender.com/health",
          "https://aravkataria-vajra.hf.space"
        ],
        author: "Arav Kataria"
      }, null, 2),
      {
        headers: { "Content-Type": "application/json" }
      }
    );
  }
};
