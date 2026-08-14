const crypto = require("node:crypto");
const { app } = require("@azure/functions");
const { TableClient } = require("@azure/data-tables");

const tableName = "Waitlist";

function json(status, body) {
  return {
    status,
    headers: { "Content-Type": "application/json" },
    jsonBody: body,
  };
}

function emailRowKey(email) {
  return crypto.createHash("sha256").update(email).digest("hex");
}

async function verifyTurnstile(token, remoteIp) {
  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) {
    throw new Error("TURNSTILE_SECRET_KEY is not configured");
  }

  const body = new URLSearchParams({ secret, response: token });
  if (remoteIp) body.set("remoteip", remoteIp);

  const response = await fetch(
    "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    { method: "POST", body },
  );

  if (!response.ok) return false;
  const result = await response.json();
  return result.success === true;
}

app.http("submit", {
  methods: ["POST"],
  authLevel: "anonymous",
  route: "submit",
  handler: async (request, context) => {
    try {
      const payload = await request.json();
      const email = String(payload.email || "").trim().toLowerCase();
      const token = String(payload.turnstileToken || "");
      const honeypot = String(payload.honeypot || "");

      if (honeypot) return json(400, { error: "Invalid submission" });
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return json(400, { error: "A valid email is required" });
      }
      if (!token) return json(400, { error: "Security verification is required" });

      const remoteIp = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
      if (!(await verifyTurnstile(token, remoteIp))) {
        return json(400, { error: "Security verification failed" });
      }

      const connectionString = process.env.AZURE_STORAGE_CONNECTION_STRING;
      if (!connectionString) throw new Error("Storage is not configured");

      const table = TableClient.fromConnectionString(connectionString, tableName);
      await table.createTable();

      const entity = {
        partitionKey: "early-access",
        rowKey: emailRowKey(email),
        email,
        createdAt: new Date().toISOString(),
        source: "caninecore.com",
      };

      try {
        await table.createEntity(entity);
      } catch (error) {
        if (error.statusCode !== 409) throw error;
        context.log("Duplicate waitlist signup", { rowKey: entity.rowKey });
      }

      return json(200, { accepted: true });
    } catch (error) {
      context.error("Waitlist submission failed", error);
      return json(500, { error: "The signup service is temporarily unavailable" });
    }
  },
});
