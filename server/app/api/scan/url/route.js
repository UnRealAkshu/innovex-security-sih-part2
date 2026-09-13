import { NextResponse } from "next/server";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ALLOWED_ORIGIN = process.env.EXTENSION_ALLOWED_ORIGIN || "*";
const EXTENSION_API_KEY = process.env.EXTENSION_API_KEY || "";

function corsHeaders() {
  return { "Access-Control-Allow-Origin": ALLOWED_ORIGIN, "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, X-Innovex-Extension-Key", "Access-Control-Max-Age": "86400", "Cache-Control": "no-store" };
}
export async function OPTIONS() { return new NextResponse(null, { status: 204, headers: corsHeaders() }); }
function json(data, status = 200) { return NextResponse.json(data, { status, headers: corsHeaders() }); }
export async function GET() { return json({ success: true, service: "Innovex Security Extension Scan API", status: "ok", engineVersion: "2.0.0", timestamp: new Date().toISOString(), urlhausConfigured: Boolean(process.env.URLHAUS_AUTH_KEY) }); }

function getSeverity(score) { if (score >= 80) return "Critical"; if (score >= 60) return "High"; if (score >= 30) return "Medium"; return "Low"; }

async function checkURLhaus(url) {
  const authKey = process.env.URLHAUS_AUTH_KEY;
  if (!authKey) return { checked: false, found: false, message: "URLhaus lookup is not configured on the scan server.", tags: [] };
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch("https://urlhaus-api.abuse.ch/v1/url/", { method: "POST", headers: { "Auth-Key": authKey, "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ url }).toString(), signal: controller.signal, cache: "no-store" });
    if (!response.ok) return { checked: false, found: false, message: "URLhaus could not be reached. Heuristic analysis was still completed.", tags: [] };
    const data = await response.json();
    const tags = Array.isArray(data?.tags) ? data.tags.filter((tag) => typeof tag === "string") : [];
    if (data?.query_status === "ok") return { checked: true, found: true, message: "URLhaus has a malicious URL record matching this URL.", reference: typeof data?.urlhaus_reference === "string" ? data.urlhaus_reference : undefined, urlStatus: typeof data?.url_status === "string" ? data.url_status : undefined, threat: typeof data?.threat === "string" ? data.threat : undefined, tags };
    if (data?.query_status === "no_results") return { checked: true, found: false, message: "URLhaus returned no matching malicious URL record. This does not guarantee safety.", tags };
    return { checked: false, found: false, message: "URLhaus returned an unexpected response. Heuristic analysis was still completed.", tags };
  } catch { return { checked: false, found: false, message: "URLhaus lookup failed. Heuristic analysis was still completed.", tags: [] }; }
  finally { clearTimeout(timeout); }
}

function analyzeUrl(rawUrl) {
  let parsed;
  try { parsed = new URL(rawUrl); } catch { return { error: "Please provide a valid URL." }; }
  const protocol = parsed.protocol.replace(":", "").toLowerCase();
  if (!["http", "https"].includes(protocol)) return { error: "Only HTTP and HTTPS URLs can be scanned." };
  const hostname = parsed.hostname.toLowerCase();
  const normalizedUrl = parsed.toString();
  let riskScore = 0;
  const indicators = [];

  if (protocol !== "https") { riskScore += 20; indicators.push("The URL does not use HTTPS."); }
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(":")) { riskScore += 25; indicators.push("The URL uses an IP address instead of a normal domain name."); }
  if (hostname.includes("xn--")) { riskScore += 20; indicators.push("The domain uses punycode, which can be used in lookalike-domain attacks."); }
  if (hostname.split(".").filter(Boolean).length >= 4) { riskScore += 10; indicators.push("The URL contains an unusually large number of subdomains."); }

  const suspiciousKeywords = ["login", "verify", "verification", "account", "secure", "security", "update", "password", "signin", "sign-in", "confirm", "bank", "wallet", "payment", "invoice", "unlock", "suspended", "urgent"];
  const lower = normalizedUrl.toLowerCase();
  const matches = [...new Set(suspiciousKeywords.filter((keyword) => lower.includes(keyword)))];
  if (matches.length) {
    const keywordScore = matches.length >= 3 ? Math.min(35, 10 + (matches.length - 3) * 5) : matches.length * 5;
    riskScore += keywordScore;
    indicators.push(`${matches.length >= 3 ? "Multiple" : "Security-sensitive"} terms detected: ${matches.slice(0, 8).join(", ")}.`);
  }

  const path = `${parsed.pathname} ${parsed.search}`.toLowerCase();
  const credentialTokens = ["login", "signin", "sign-in", "verify", "verification", "password", "account", "confirm", "secure"];
  const pathMatches = credentialTokens.filter((keyword) => path.includes(keyword));
  if (pathMatches.length >= 4) { riskScore += 20; indicators.push("The URL path contains multiple credential or account-action terms."); }
  if (/login.*(verify|verification|password)|signin.*(verify|password)/i.test(path)) { riskScore += 10; indicators.push("Authentication and verification steps appear together in the URL path."); }

  if (normalizedUrl.length > 180) { riskScore += 10; indicators.push("The URL is unusually long."); }
  if (normalizedUrl.includes("@")) { riskScore += 20; indicators.push("The URL contains an @ symbol or embedded credential-like information."); }
  if (parsed.port && !["80", "443"].includes(parsed.port)) { riskScore += 15; indicators.push("The URL uses a non-standard network port."); }
  if ([...parsed.searchParams.keys()].length >= 5) { riskScore += 10; indicators.push("The URL contains many query parameters."); }

  return { normalizedUrl, hostname, protocol, riskScore: Math.min(100, Math.max(0, riskScore)), indicators };
}

function applyPageSignals(baseScore, baseIndicators, signals) {
  let riskScore = baseScore;
  const indicators = [...baseIndicators];
  if (!signals || typeof signals !== "object") return { riskScore, indicators };
  if (signals.knownSecurityTestPage) { riskScore = 100; indicators.push("Known safe AMTSO phishing-simulation test page detected."); indicators.push("This page is a security test, not a real malicious website."); }

  const passwordFields = Number(signals.passwordFields) || 0;
  const emailFields = Number(signals.emailFields) || 0;
  const sensitiveFields = Number(signals.sensitiveFields) || 0;
  const externalFormTargets = Number(signals.externalFormTargets) || 0;
  const authWords = Array.isArray(signals.matchedAuthWords) ? signals.matchedAuthWords : [];
  if (passwordFields > 0) { riskScore += 15; indicators.push("The page contains a password input field."); }
  if (passwordFields > 0 && (emailFields > 0 || authWords.length > 0)) { riskScore += 15; indicators.push("The page appears to collect login/account credentials."); }
  if (sensitiveFields > 0) { riskScore += 15; indicators.push("The page contains a field associated with sensitive information."); }
  if (externalFormTargets > 0) { riskScore += 25; indicators.push("A form submits data to an external origin."); }
  if (authWords.length >= 2 && passwordFields > 0) { riskScore += 5; indicators.push("Multiple authentication-related terms appear alongside a password field."); }
  if (signals.hasPaymentLanguage && sensitiveFields > 0) { riskScore += 15; indicators.push("Payment or billing language appears near sensitive input fields."); }
  if (signals.hasUrgencyLanguage && (passwordFields > 0 || sensitiveFields > 0)) { riskScore += 15; indicators.push("Urgency language appears on a page requesting sensitive information."); }
  return { riskScore: Math.min(100, Math.max(0, riskScore)), indicators: [...new Set(indicators)] };
}

export async function POST(request) {
  try {
    if (EXTENSION_API_KEY) { const suppliedKey = request.headers.get("x-innovex-extension-key") || ""; if (suppliedKey !== EXTENSION_API_KEY) return json({ success: false, error: "Invalid extension API key." }, 401); }
    const body = await request.json();
    const rawUrl = typeof body?.url === "string" ? body.url.trim() : "";
    const pageSignals = body?.pageSignals && typeof body.pageSignals === "object" ? body.pageSignals : null;
    if (!rawUrl) return json({ success: false, error: "Please provide a URL." }, 400);
    if (rawUrl.length > 2048) return json({ success: false, error: "URL is too long." }, 400);

    const analysis = analyzeUrl(rawUrl);
    if (analysis.error) return json({ success: false, error: analysis.error }, 400);
    const threatIntelligence = await checkURLhaus(analysis.normalizedUrl);
    const pageAnalysis = applyPageSignals(analysis.riskScore, analysis.indicators, pageSignals);
    let riskScore = pageAnalysis.riskScore;
    const indicators = [...pageAnalysis.indicators];
    if (threatIntelligence.found) { riskScore = 100; indicators.push("URLhaus identified this URL as a known malicious URL."); if (threatIntelligence.threat) indicators.push(`URLhaus threat classification: ${threatIntelligence.threat}.`); if (threatIntelligence.urlStatus) indicators.push(`URLhaus status: ${threatIntelligence.urlStatus}.`); }
    riskScore = Math.min(100, Math.max(0, riskScore));
    const severity = getSeverity(riskScore);
    const threatDetected = riskScore >= 30 || threatIntelligence.found;
    const confidence = threatIntelligence.found ? 99 : Math.min(99, Math.max(70, 100 - Math.abs(50 - riskScore)));
    let recommendation = "The page appears relatively low risk based on the available checks. Still verify the source before entering sensitive information.";
    if (severity === "Medium") recommendation = "Use caution. Review the page and verify the source independently before entering sensitive information.";
    if (severity === "High") recommendation = "Avoid using this page until it has been independently verified. Do not enter passwords or payment information.";
    if (severity === "Critical") recommendation = "Do not use this page. Treat it as potentially dangerous and avoid entering credentials or sensitive information.";
    if (threatIntelligence.found) recommendation = "Do not open this URL. URLhaus identified it as a known malicious URL. Avoid entering credentials, payment information or other sensitive data.";
    return json({ success: true, engineVersion: "2.0.0", url: analysis.normalizedUrl, riskScore, severity, confidence, threatDetected, domain: analysis.hostname, protocol: analysis.protocol, analysisType: threatIntelligence.checked ? "URL heuristic + page signals + URLhaus threat intelligence" : "URL heuristic + page signals", indicators: [...new Set(indicators)], recommendation, threatIntelligence, pageSignals });
  } catch (error) {
    console.error("Extension URL scan error:", error);
    return json({ success: false, error: "Something went wrong while analyzing the URL." }, 500);
  }
}
