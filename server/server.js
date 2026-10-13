require("dotenv").config();

const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const { google } = require("googleapis");

const app = express();
const PORT = Number(process.env.PORT || 4000);
const AI_SERVICE_URL = (
  process.env.AI_SERVICE_URL || "http://127.0.0.1:8000"
).replace(/\/+$/, "");

const REQUIRED_ENV = [
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
  "GOOGLE_REDIRECT_URI",
  "SESSION_SECRET",
];

const missingEnv = REQUIRED_ENV.filter((key) => !process.env[key]);

if (missingEnv.length) {
  console.error("Missing .env variables:", missingEnv.join(", "));
  process.exit(1);
}

app.disable("x-powered-by");
app.use(express.json({ limit: "100kb" }));

app.use(
  session({
    name: "mailguard.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 60 * 60 * 1000,
    },
  })
);

const SCOPES = [
  "https://www.googleapis.com/auth/gmail.readonly",
];

function createOAuthClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI
  );
}

function getGmailClient(req) {
  const tokens = req.session?.gmailTokens;
  if (!tokens) return null;

  const auth = createOAuthClient();
  auth.setCredentials(tokens);

  return google.gmail({ version: "v1", auth });
}

function getHeader(headers = [], name) {
  return (
    headers.find(
      (header) =>
        header.name?.toLowerCase() === name.toLowerCase()
    )?.value || ""
  );
}

function decodePart(part) {
  if (!part?.body?.data) return "";

  try {
    return Buffer.from(part.body.data, "base64url").toString("utf8");
  } catch {
    return "";
  }
}

function collectMimeText(part, output = { plain: [], html: [] }) {
  if (!part) return output;

  const mime = (part.mimeType || "").toLowerCase();
  const text = decodePart(part);

  if (text.trim()) {
    if (mime === "text/plain") output.plain.push(text);
    if (mime === "text/html") output.html.push(text);
  }

  for (const child of part.parts || []) {
    collectMimeText(child, output);
  }

  return output;
}

function htmlToText(html) {
  return html
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|li|tr|h[1-6])>/gi, "\n")
    .replace(/<[^>]*>/g, " ")
    .replace(/&nbsp;|&#160;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/[ \t]+/g, " ")
    .replace(/\n\s*\n+/g, "\n")
    .trim();
}

function extractText(payload) {
  const collected = collectMimeText(payload);

  if (collected.plain.length) {
    return collected.plain.join("\n").trim();
  }

  if (collected.html.length) {
    return htmlToText(collected.html.join("\n"));
  }

  const fallback = decodePart(payload);

  return (payload?.mimeType || "").toLowerCase() === "text/html"
    ? htmlToText(fallback)
    : fallback.trim();
}

// Normalize Python results without turning missing scores into zero.
function normalizeAnalysis(raw) {
  const nested =
    raw?.analysis && typeof raw.analysis === "object"
      ? raw.analysis
      : raw?.ai_result && typeof raw.ai_result === "object"
      ? raw.ai_result
      : raw?.output && typeof raw.output === "object"
      ? raw.output
      : {};

  const candidates = [
    raw?.risk_score,
    raw?.riskScore,
    raw?.score,
    nested?.risk_score,
    nested?.riskScore,
    nested?.score,
  ];

  const rawScore = candidates.find(
    (value) =>
      value !== null &&
      value !== undefined &&
      value !== "" &&
      Number.isFinite(Number(value)) &&
      Number(value) >= 0 &&
      Number(value) <= 100
  );

  const score =
    rawScore === undefined ? null : Number(rawScore);

  const rawVerdict =
    raw?.verdict ?? nested?.verdict;

  const verdict =
    typeof rawVerdict === "string" && rawVerdict.trim()
      ? rawVerdict
      : score === null
      ? "unavailable"
      : score >= 70
      ? "high_risk"
      : score >= 40
      ? "suspicious"
      : score >= 20
      ? "medium_risk"
      : "low_risk";

  const rawReasons = raw?.reasons ?? nested?.reasons;

  return {
    risk_score: score,
    verdict,
    reasons: Array.isArray(rawReasons)
      ? rawReasons.filter((reason) => typeof reason === "string")
      : [],
    analysis_status:
      score !== null && verdict !== "unavailable"
        ? "completed"
        : "incomplete",
    model_type:
      raw?.model_type ?? nested?.model_type ?? "unknown",
    warning: raw?.warning ?? nested?.warning ?? null,
  };
}

function publicMessage(message) {
  const analysis = {
    risk_score: message.risk_score ?? null,
    verdict: message.verdict || "unavailable",
    reasons: message.reasons || [],
    analysis_status: message.analysis_status || "not_started",
    model_type: message.model_type || "unknown",
    warning: message.warning || null,
  };

  return {
    ...message,
    from: message.sender || message.from || "",
    ...analysis,
    analysis,
  };
}

// Health endpoint
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    app: "MailGuard AI",
    backendPort: PORT,
    aiServiceUrl: AI_SERVICE_URL,
  });
});

// Gmail connection status
app.get("/api/gmail/status", async (req, res) => {
  const gmail = getGmailClient(req);

  if (!gmail) {
    return res.json({ connected: false });
  }

  try {
    const profile = await gmail.users.getProfile({ userId: "me" });

    res.json({
      connected: true,
      email: profile.data.emailAddress,
    });
  } catch (error) {
    console.error("Gmail status error:", error.message);
    res.status(502).json({
      error: "Could not verify Gmail connection. Reconnect Gmail.",
    });
  }
});

// Start Google OAuth
app.get("/api/auth/google", (req, res) => {
  const state = crypto.randomBytes(32).toString("hex");
  req.session.oauthState = state;

  const authUrl = createOAuthClient().generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    include_granted_scopes: true,
    scope: SCOPES,
    state,
  });

  req.session.save((error) => {
    if (error) {
      console.error("OAuth session error:", error.message);
      return res.status(500).send(
        "Could not start Google authentication."
      );
    }

    res.redirect(authUrl);
  });
});

// Google OAuth callback
app.get("/api/auth/google/callback", async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.status(400).send(
      "Google authorization was not completed."
    );
  }

  if (
    typeof state !== "string" ||
    !req.session.oauthState ||
    state !== req.session.oauthState
  ) {
    return res.status(403).send(
      "Invalid OAuth state. Please reconnect Gmail."
    );
  }

  delete req.session.oauthState;

  if (typeof code !== "string") {
    return res.status(400).send(
      "Missing Google authorization code."
    );
  }

  try {
    const auth = createOAuthClient();
    const { tokens } = await auth.getToken(code);

    if (!tokens.access_token) {
      throw new Error("Google returned no access token.");
    }

    req.session.gmailTokens = {
      ...req.session.gmailTokens,
      ...tokens,
    };

    req.session.save((saveError) => {
      if (saveError) {
        console.error("Session save error:", saveError.message);
        return res.status(500).send(
          "Could not save Gmail session."
        );
      }

      const frontendUrl = (
        process.env.FRONTEND_URL || "http://localhost:5173"
      ).replace(/\/+$/, "");

      res.redirect(`${frontendUrl}/?gmail=connected`);
    });
  } catch (err) {
    console.error("OAuth callback error:", err.message);
    res.status(500).send(
      "Gmail connection failed. Check backend terminal."
    );
  }
});

// Fetch the latest 10 Inbox messages
async function getInboxMessages(gmail) {
  const list = await gmail.users.messages.list({
    userId: "me",
    labelIds: ["INBOX"],
    maxResults: 10,
  });

  const items = list.data.messages || [];

  return Promise.all(
    items.map(async (item) => {
      const response = await gmail.users.messages.get({
        userId: "me",
        id: item.id,
        format: "full",
      });

      const payload = response.data.payload || {};
      const headers = payload.headers || [];
      const snippet = response.data.snippet || "";
      const sender = getHeader(headers, "From");
      const subject =
        getHeader(headers, "Subject") || "(No subject)";

      const extractedBody = extractText(payload);
      const body = [extractedBody, snippet]
        .filter(Boolean)
        .join("\n")
        .slice(0, 20000);

      return {
        id: item.id,
        sender,
        from: sender,
        subject,
        date: getHeader(headers, "Date"),
        snippet,
        labels: response.data.labelIds || [],
        body,
        body_length: body.length,
      };
    })
  );
}

// Recent Inbox endpoint
app.get("/api/gmail/recent", async (req, res) => {
  const gmail = getGmailClient(req);

  if (!gmail) {
    return res.status(401).json({
      error: "Connect Gmail first.",
    });
  }

  try {
    const messages = await getInboxMessages(gmail);

    res.json({
      count: messages.length,
      messages: messages.map((message) =>
        publicMessage({
          ...message,
          risk_score: null,
          verdict: "not_analyzed",
          reasons: [],
          analysis_status: "not_started",
        })
      ),
    });
  } catch (error) {
    console.error("Fetching Inbox failed:", error.message);
    res.status(502).json({
      error: "Could not fetch Inbox messages.",
    });
  }
});

// Analyze recent Inbox messages
app.post("/api/gmail/analyze", async (req, res) => {
  const gmail = getGmailClient(req);

  if (!gmail) {
    return res.status(401).json({
      error: "Connect Gmail first.",
    });
  }

  try {
    const emails = await getInboxMessages(gmail);

    const results = await Promise.all(
      emails.map(async (email) => {
        if (!email.sender && !email.subject && !email.body.trim()) {
          return publicMessage({
            ...email,
            risk_score: null,
            verdict: "unavailable",
            reasons: ["No usable email content was available."],
            analysis_status: "incomplete",
            model_type: "unknown",
          });
        }

        let normalized;

        try {
          console.log(
            `[MailGuard] Analyzing "${email.subject}" | body chars: ${email.body.length}`
          );

          const aiResponse = await fetch(
            `${AI_SERVICE_URL}/analyze`,
            {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify({
                sender: email.sender,
                subject: email.subject,
                body: email.body,
              }),
              signal: AbortSignal.timeout(20000),
            }
          );

          if (!aiResponse.ok) {
            const details = await aiResponse.text().catch(() => "");
            throw new Error(
              `Python AI HTTP ${aiResponse.status}: ${details.slice(0, 250)}`
            );
          }

          const raw = await aiResponse.json();

console.log("[MailGuard] Email sent to AI:", {
  subject: email.subject,
  bodyLength: (email.body || "").length,
  bodyPreview: (email.body || "").slice(0, 300),
});

          console.log("[MailGuard] Raw Python response:", {
            subject: email.subject,
            risk_score: raw?.risk_score,
            nested_risk_score: raw?.analysis?.risk_score,
            model_type: raw?.model_type,
          });

          normalized = normalizeAnalysis(raw);

          console.log("[MailGuard] AI result:", {
            id: email.id,
            subject: email.subject,
            risk_score: normalized.risk_score,
            verdict: normalized.verdict,
            model_type: normalized.model_type,
            reasons: normalized.reasons,
          });

          if (normalized.analysis_status !== "completed") {
            console.warn(
              "[MailGuard] Incomplete analyzer response:",
              raw
            );
          }
        } catch (error) {
          console.error(
            `[MailGuard] Analysis failed for "${email.subject}":`,
            error.message
          );

          normalized = {
            risk_score: null,
            verdict: "unavailable",
            reasons: ["Python analysis failed. Please retry."],
            analysis_status: "failed",
            model_type: "unknown",
            warning: error.message,
          };
        }

        return publicMessage({
          ...email,
          ...normalized,
        });
      })
    );

    const completed = results.filter(
      (item) => item.analysis_status === "completed"
    ).length;

    const failed = results.filter(
      (item) =>
        item.analysis_status === "failed" ||
        item.analysis_status === "incomplete"
    ).length;

    res.json({
      count: results.length,
      completed,
      failed,
      results,
    });
  } catch (error) {
    console.error("Gmail analysis route failed:", error.message);
    res.status(502).json({
      error: "Could not analyze Gmail messages.",
    });
  }
});

// Disconnect Gmail
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      console.error("Logout failed:", error.message);
      return res.status(500).json({
        error: "Could not end the session.",
      });
    }

    res.clearCookie("mailguard.sid");
    res.json({ success: true });
  });
});

// Unknown API endpoint
app.use("/api", (req, res) => {
  res.status(404).json({
    error: "API endpoint not found.",
  });
});

// Start backend
app.listen(PORT, () => {
  console.log(`MailGuard AI backend: http://localhost:${PORT}`);
  console.log(`Python AI service: ${AI_SERVICE_URL}`);
});