

import { useEffect, useState } from "react";

import {

  ShieldCheck,

  Mail,

  Inbox,

  ShieldAlert,

  RefreshCw,

  LockKeyhole,

  Activity,

  Search,

  AlertTriangle,

  CheckCircle2,

  XCircle,

} from "lucide-react";

import "./App.css";



const API = "/api";



const ANALYSIS_WARNING =

  "Rule-based preliminary analysis, not a trained ML model. A low score does not prove an email is genuine.";



function normalizeAnalysis(result, fallbackId) {
  // Backend may return analysis fields either nested or at the top level.
  const nested =
    result?.analysis ??
    result?.ai_result ??
    result?.output ??
    {};

  // Prefer the first real score, rather than letting an incomplete nested
  // object hide a valid top-level risk_score.
  const scoreCandidates = [
    nested?.risk_score,
    nested?.riskScore,
    nested?.score,
    result?.risk_score,
    result?.riskScore,
    result?.score,
  ];

  const rawScore = scoreCandidates.find(
    (value) =>
      value !== null &&
      value !== undefined &&
      value !== "" &&
      Number.isFinite(Number(value)) &&
      Number(value) >= 0 &&
      Number(value) <= 100
  );

  const score =
    rawScore === undefined
      ? null
      : Number(rawScore);

  const verdict =
    nested?.verdict ??
    result?.verdict ??
    (score === null
      ? "unavailable"
      : score >= 70
      ? "high_risk"
      : score >= 40
      ? "suspicious"
      : score >= 20
      ? "medium_risk"
      : "low_risk");

  const rawStatus =
    result?.analysis_status ??
    result?.status ??
    nested?.analysis_status;

  const failed = rawStatus === "failed" || rawStatus === "error";
  const completed = !failed && score !== null && rawStatus !== "pending";

  const reasons = Array.isArray(nested?.reasons)
    ? nested.reasons
    : Array.isArray(result?.reasons)
    ? result.reasons
    : [];

  return {
    ...result,
    id:
      result?.id ??
      result?.messageId ??
      result?.message_id ??
      fallbackId,
    risk_score: score,
    verdict,
    reasons,
    model_type:
      nested?.model_type ??
      result?.model_type ??
      "unknown",
    warning:
      nested?.warning ??
      result?.warning ??
      ANALYSIS_WARNING,
    analysis_status: failed
      ? "failed"
      : completed
      ? "completed"
      : "unavailable",
  };
}

function riskLabel(item) {

  if (

    item.analysis_status !== "completed" ||

    item.risk_score === null ||

    item.risk_score === undefined ||

    !Number.isFinite(Number(item.risk_score))

  ) {

    return "Unavailable";

  }



  const score = Number(item.risk_score);



  if (score >= 70) return "High risk";

  if (score >= 40) return "Suspicious";

  if (score >= 20) return "Medium risk";



  return "Low risk";

}



function RiskBadge({ item }) {

  const label = riskLabel(item);



  const styles = {

    "High risk": {

      color: "#fecaca",

      background: "#451a1a",

      borderColor: "#b91c1c",

    },

    Suspicious: {

      color: "#fde68a",

      background: "#422006",

      borderColor: "#a16207",

    },

    "Medium risk": {

      color: "#fde68a",

      background: "#422006",

      borderColor: "#a16207",

    },

    "Low risk": {

      color: "#a7f3d0",

      background: "#064e3b",

      borderColor: "#047857",

    },

    Unavailable: {

      color: "#cbd5e1",

      background: "#1e293b",

      borderColor: "#475569",

    },

  };



  const icons = {

    "High risk": <AlertTriangle size={14} />,

    Suspicious: <ShieldAlert size={14} />,

    "Medium risk": <ShieldAlert size={14} />,

    "Low risk": <CheckCircle2 size={14} />,

    Unavailable: <XCircle size={14} />,

  };



  return (

    <span

      style={{

        ...styles[label],

        display: "inline-flex",

        alignItems: "center",

        gap: 6,

        border: "1px solid",

        borderRadius: 20,

        padding: "6px 12px",

        fontSize: 12,

        fontWeight: 700,

      }}

    >

      {icons[label]}

      {label}

    </span>

  );

}



export default function App() {

  const [account, setAccount] = useState(null);

  const [messages, setMessages] = useState([]);

  const [analysisById, setAnalysisById] = useState({});

  const [loading, setLoading] = useState(true);

  const [analyzing, setAnalyzing] = useState(false);

  const [error, setError] = useState("");

  const [notice, setNotice] = useState("");



  async function requestJSON(url, options = {}) {

    const response = await fetch(url, options);



    const contentType =

      response.headers.get("content-type") || "";



    if (!contentType.includes("application/json")) {

      throw new Error(

        `Non-JSON response (HTTP ${response.status}). Check the Node.js backend and Vite proxy.`

      );

    }



    const data = await response.json();



    if (!response.ok) {

      throw new Error(

        data.error ||

          data.message ||

          `Request failed with HTTP ${response.status}`

      );

    }



    return data;

  }



  async function loadDashboard() {

    setLoading(true);

    setError("");

    setNotice("");



    try {

      const status = await requestJSON(

        `${API}/gmail/status`

      );



      if (!status.connected) {

        setAccount(null);

        setMessages([]);

        setAnalysisById({});

        return;

      }



      setAccount(status);



      const data = await requestJSON(

        `${API}/gmail/recent`

      );



      const inboxMessages = Array.isArray(data.messages)

        ? data.messages

        : [];



      setMessages(inboxMessages);



      const currentIds = new Set(

        inboxMessages.map((message) => message.id)

      );



      setAnalysisById((previous) =>

        Object.fromEntries(

          Object.entries(previous).filter(([id]) =>

            currentIds.has(id)

          )

        )

      );

    } catch (err) {

      setError(

        err.message || "Unable to load the dashboard."

      );

    } finally {

      setLoading(false);

    }

  }



  useEffect(() => {

    loadDashboard();

  }, []);



  async function analyzeEmails() {

    if (!account) {

      setError("Connect Gmail first.");

      return;

    }



    setAnalyzing(true);

    setError("");

    setNotice("");



    try {

      const data = await requestJSON(

        `${API}/gmail/analyze`,

        {

          method: "POST",

          headers: {

            "Content-Type": "application/json",

          },

          body: JSON.stringify({}),

        }

      );



      const results = Array.isArray(data.results)

        ? data.results

        : [];



      const nextResults = {};



      results.forEach((result, index) => {

        // Prefer the exact Gmail message ID.

        // Use the corresponding Inbox ID only when the

        // backend has omitted an ID from its result.

        const resultId =

          result.id ??

          result.messageId ??

          result.message_id ??

          messages[index]?.id;



        if (!resultId) {

          console.warn(

            "Analysis result has no matching Gmail ID:",

            result

          );

          return;

        }



        const normalized = normalizeAnalysis(

          result,

          resultId

        );



        nextResults[resultId] = normalized;

      });



      console.log(

        "MailGuard AI analysis response:",

        data

      );



      console.table(

        Object.values(nextResults).map((item) => ({

          id: item.id,

          subject: item.subject,

          risk_score: item.risk_score,

          verdict: item.verdict,

          status: item.analysis_status,

          reasons: item.reasons.join("; "),

        }))

      );



      setAnalysisById((previous) => ({

        ...previous,

        ...nextResults,

      }));



      const completed = Object.values(nextResults).filter(

        (item) => item.analysis_status === "completed"

      ).length;



      const failed = results.length - completed;



      setNotice(

        `Analysis finished: ${completed} completed, ${failed} unavailable or failed, out of ${data.count ?? results.length} emails.`

      );



      if (results.length === 0) {

        setNotice(

          "No results returned. Check the Node.js backend response."

        );

      }



      if (completed === 0 && results.length > 0) {

        setError(

          "The backend returned results, but no valid risk scores were found. Check the Console and Node.js response mapping."

        );

      }

    } catch (err) {

      setError(

        err.message || "Email analysis failed."

      );

    } finally {

      setAnalyzing(false);

    }

  }



  async function disconnect() {

    setError("");

    setNotice("");



    try {

      await requestJSON(`${API}/auth/logout`, {

        method: "POST",

      });



      setAccount(null);

      setMessages([]);

      setAnalysisById({});

    } catch (err) {

      setError(

        err.message || "Unable to disconnect Gmail."

      );

    }

  }



  const displayedMessages = messages.map((message) => ({

    ...message,

    ...(analysisById[message.id] || {}),

    id: message.id,

  }));



  const completedResults = Object.values(

    analysisById

  ).filter(

    (item) =>

      item.analysis_status === "completed" &&

      item.risk_score !== null &&

      item.risk_score !== undefined

  );



  const threatsDetected = completedResults.filter(

    (item) => Number(item.risk_score) >= 40

  ).length;



  const highRiskCount = completedResults.filter(

    (item) => Number(item.risk_score) >= 70

  ).length;



  return (

    <div className="app-shell">

      <aside className="sidebar">

        <div className="brand">

          <ShieldCheck size={30} />

          <div>

            <strong>MailGuard AI</strong>

            <small>EMAIL SECURITY</small>

          </div>

        </div>



        <p className="nav-heading">WORKSPACE</p>



        <div className="nav-item active">

          <Activity size={18} />

          Overview

        </div>



        <div className="nav-item">

          <Inbox size={18} />

          Inbox Activity

        </div>



        <div className="nav-item">

          <ShieldAlert size={18} />

          Threat Protection

        </div>



        <div className="privacy">

          <LockKeyhole size={22} />

          <strong>Privacy first</strong>

          <p>

            Gmail access uses Google OAuth. Your Gmail

            password is never requested.

          </p>

        </div>

      </aside>



      <main className="main">

        <header className="topbar">

          <div>

            <span className="eyebrow">

              EMAIL SECURITY CENTER

            </span>

            <h1>Overview</h1>

          </div>



          <button

            className="secondary-button"

            onClick={loadDashboard}

            disabled={loading || analyzing}

          >

            <RefreshCw size={16} />

            Refresh

          </button>

        </header>



        <section className="hero">

          <div>

            <span className="pill">

              <ShieldCheck size={15} />

              SMART EMAIL PROTECTION

            </span>



            <h2>

              Your inbox.

              <br />

              A smarter layer of security.

            </h2>



            <p>

              Detect suspicious emails and find legitimate

              messages that may have been misplaced.

            </p>



            {account ? (

              <div className="connected">

                <Mail size={18} />

                <span>{account.email}</span>

                <button

                  onClick={disconnect}

                  disabled={analyzing}

                >

                  Disconnect

                </button>

              </div>

            ) : (

              <a

                className="primary-button"

                href={`${API}/auth/google`}

              >

                <Mail size={18} />

                Connect Gmail

              </a>

            )}

          </div>



          <div className="hero-shield">

            <ShieldCheck size={100} strokeWidth={1.2} />

          </div>

        </section>



        {error && (

          <div className="error" role="alert">

            {error}

          </div>

        )}



        {notice && (

          <div

            role="status"

            style={{

              padding: 14,

              margin: "16px 0",

              borderRadius: 10,

              background: "#102d27",

              border: "1px solid #166534",

              color: "#bbf7d0",

              overflowWrap: "anywhere",

            }}

          >

            {notice}

          </div>

        )}



        <section className="stats">

          <article className="stat">

            <Mail size={21} />

            <span>Gmail connection</span>

            <strong>

              {loading

                ? "Loading..."

                : account

                ? "Connected"

                : "Not connected"}

            </strong>

          </article>



          <article className="stat">

            <Search size={21} />

            <span>Emails analyzed</span>

            <strong>{completedResults.length}</strong>

            <small>Successfully analyzed this session</small>

          </article>



          <article className="stat">

            <ShieldAlert size={21} />

            <span>Potential threats</span>

            <strong>{threatsDetected}</strong>

            <small>

              Scores of 40 or higher; verify manually

            </small>

          </article>



          <article className="stat">

            <AlertTriangle size={21} />

            <span>High-risk emails</span>

            <strong>{highRiskCount}</strong>

            <small>Scores of 70 or higher</small>

          </article>

        </section>



        <section className="panel">

          <div className="panel-heading">

            <div>

              <h3>Recent inbox activity</h3>

              <p>Latest messages from your Gmail Inbox</p>

            </div>



            <button

              className="secondary-button"

              onClick={loadDashboard}

              disabled={loading || analyzing}

            >

              <RefreshCw size={15} />

              Refresh

            </button>

          </div>



          {account && (

            <div

              style={{

                display: "flex",

                flexWrap: "wrap",

                alignItems: "center",

                justifyContent: "space-between",

                gap: 14,

                padding: "18px 0",

                borderTop: "1px solid #26364d",

                borderBottom: "1px solid #26364d",

              }}

            >

              <p style={{ margin: 0, lineHeight: 1.6 }}>

                Analyze up to 10 recent Inbox messages for

                potential phishing indicators.

              </p>



              <button

                className="primary-button"

                onClick={analyzeEmails}

                disabled={analyzing || loading}

              >

                <ShieldCheck size={17} />

                {analyzing

                  ? "Analyzing emails..."

                  : "Analyze emails"}

              </button>

            </div>

          )}



          {loading ? (

            <p className="empty">

              Checking Gmail connection...

            </p>

          ) : !account ? (

            <div className="empty">

              <Inbox size={34} />

              <strong>Connect Gmail to get started</strong>

              <p>Your recent messages will appear here.</p>

            </div>

          ) : displayedMessages.length === 0 ? (

            <p className="empty">

              No Inbox messages found.

            </p>

          ) : (

            <div className="messages">

              {displayedMessages.map((message) => {

                const reasons = Array.isArray(message.reasons)

                  ? message.reasons

                  : [];



                const hasAnalysis =

                  message.analysis_status === "completed";



                return (

                  <article

                    className="message"

                    key={message.id}

                    style={{

                      display: "grid",

                      gridTemplateColumns:

                        "24px minmax(0, 1fr)",

                      gap: 14,

                      padding: "22px 0",

                      borderBottom: "1px solid #26364d",

                    }}

                  >

                    <Mail size={20} />



                    <div style={{ minWidth: 0 }}>

                      <strong

                        style={{ overflowWrap: "anywhere" }}

                      >

                        {message.subject || "(No subject)"}

                      </strong>



                      <p style={{ overflowWrap: "anywhere" }}>

                        {message.from ||

                          message.sender ||

                          "Unknown sender"}

                      </p>



                      <small

                        style={{

                          display: "block",

                          lineHeight: 1.7,

                          overflowWrap: "anywhere",

                        }}

                      >

                        {message.snippet ||

                          message.bodyPreview ||

                          "No preview available."}

                      </small>



                      <div

                        style={{

                          display: "flex",

                          alignItems: "center",

                          flexWrap: "wrap",

                          gap: 10,

                          marginTop: 14,

                        }}

                      >

                        <RiskBadge item={message} />



                        {hasAnalysis && (

                          <strong

                            style={{

                              fontSize: 13,

                              color: "#cbd5e1",

                            }}

                          >

                            Risk score: {message.risk_score}/100

                          </strong>

                        )}



                        {!hasAnalysis &&

                          message.analysis_status !== "failed" && (

                            <small style={{ color: "#94a3b8" }}>

                              Run Analyze emails to get a risk score.

                            </small>

                          )}

                      </div>



                      {hasAnalysis && reasons.length > 0 && (

                        <div style={{ marginTop: 12 }}>

                          <strong style={{ fontSize: 13 }}>

                            Detection reasons

                          </strong>



                          <ul

                            style={{

                              marginTop: 8,

                              paddingLeft: 20,

                              lineHeight: 1.8,

                            }}

                          >

                            {reasons.map((reason, index) => (

                              <li key={`${message.id}-${index}`}>

                                {reason}

                              </li>

                            ))}

                          </ul>

                        </div>

                      )}



                      {hasAnalysis && reasons.length === 0 && (

                        <p style={{ color: "#94a3b8" }}>

                          No configured phishing indicators were

                          detected. This does not guarantee safety.

                        </p>

                      )}



                      {message.analysis_status === "failed" && (

                        <p style={{ color: "#fca5a5" }}>

                          Analysis failed. Check the backend logs

                          and try again.

                        </p>

                      )}



                      {hasAnalysis && message.warning && (

                        <small

                          style={{

                            display: "block",

                            marginTop: 10,

                            color: "#fbbf24",

                            lineHeight: 1.6,

                          }}

                        >

                          {message.warning}

                        </small>

                      )}



                      {hasAnalysis && message.model_type && (

                        <small

                          style={{

                            display: "block",

                            marginTop: 8,

                            color: "#94a3b8",

                          }}

                        >

                          Model: {message.model_type}

                        </small>

                      )}



                      {hasAnalysis && (

                        <small

                          style={{

                            display: "block",

                            marginTop: 8,

                            color: "#fbbf24",

                          }}

                        >

                          Preliminary risk assessment only.

                          Verify suspicious emails independently.

                        </small>

                      )}



                      {message.date && (

                        <small

                          style={{

                            display: "block",

                            marginTop: 8,

                            color: "#94a3b8",

                          }}

                        >

                          {new Date(message.date).toLocaleString()}

                        </small>

                      )}

                    </div>

                  </article>

                );

              })}

            </div>

          )}

        </section>



        <section className="panel status-panel">

          <ShieldCheck size={25} />

          <div>

            <h3>Security engine status</h3>

            <p>

              Gmail access is read-only. The Python service

              currently uses a rule-based heuristic baseline.

              Scores are indicators, not proof that an email is

              malicious or safe.

            </p>

          </div>

          <span className="status-badge">IN DEVELOPMENT</span>

        </section>



        <footer>

          MailGuard AI · Secure email starts here

        </footer>

      </main>

    </div>

  );

}
