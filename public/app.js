"use strict";

document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const messageInput = document.getElementById("message-input");
  const languageSelect = document.getElementById("language-select");
  const charCount = document.getElementById("char-count");
  const clearBtn = document.getElementById("clear-btn");
  const analyzeBtn = document.getElementById("analyze-btn");
  const analyzeBtnText = document.getElementById("analyze-btn-text");
  const statusPill = document.getElementById("system-status");
  const statusText = document.getElementById("status-text");

  const alertBox = document.getElementById("alert-box");
  const alertTitle = document.getElementById("alert-title");
  const alertMessage = document.getElementById("alert-message");
  const alertClose = document.getElementById("alert-close");

  const resultsSection = document.getElementById("results-section");
  const riskCard = document.getElementById("risk-card");
  const riskBadge = document.getElementById("risk-badge");
  const riskSubtitle = document.getElementById("risk-subtitle");
  const resultLanguageTag = document.getElementById("result-language-tag");
  const riskSummaryText = document.getElementById("risk-summary-text");
  const indicatorsList = document.getElementById("indicators-list");
  const adviceList = document.getElementById("advice-list");
  const disclaimerText = document.getElementById("disclaimer-text");

  const sampleButtons = document.querySelectorAll(".sample-btn");

  // Sample Messages
  const SAMPLES = {
    kyc: "URGENT: Your SBI account 4321 is suspended due to missing PAN/KYC. Restore access immediately by verifying your details: http://sbi-kyc-reactivate.xyz/login",
    lottery: "CONGRATULATIONS! You have won $50,000 in the Google International Annual Sweepstakes. Send your full name, bank account, and WhatsApp number to claim your prize immediately.",
    job: "Part-time job offer! Earn 5,000 to 15,000 INR daily by liking YouTube videos and rating hotels on Telegram. No experience needed. Join immediately: https://t.me/quickpayjobs",
    legit: "Dear Customer, your account ending in 1024 was credited with INR 2,500.00 on 24-Oct via UPI. Ref 429381. If this was not you, call 1800-0000.",
    telugu_kyc: "ముఖ్యమైన గమనిక: మీ SBI బ్యాంక్ ఖాతా KYC గడువు ముగిసింది. మీ అకౌంట్ శాశ్వతంగా బ్లాక్ కాకుండా ఉండటానికి వెంటనే ఈ లింక్ ద్వారా పాన్‌కార్డ్ అప్‌డేట్ చేయండి: http://sbi-telugu-update.top"
  };

  // Check Backend Health
  async function checkHealth() {
    try {
      const res = await fetch("/api/health");
      if (!res.ok) throw new Error("Health check returned status " + res.status);
      const data = await res.json();

      statusPill.className = "status-pill";
      if (data.apiKeyConfigured) {
        statusPill.classList.add("status-online");
        statusText.textContent = `Online • ${data.model || "Gemma 4"}`;
      } else {
        statusPill.classList.add("status-pending");
        statusText.textContent = `API Key Pending (.env) • ${data.model || "Gemma 4"}`;
      }
    } catch {
      statusPill.className = "status-pill status-error";
      statusText.textContent = "Backend Offline";
    }
  }

  // Update Character Count
  function updateCharCount() {
    const len = messageInput.value.length;
    charCount.textContent = len.toLocaleString();
    if (len > 9000) {
      charCount.parentElement.classList.add("limit-near");
    } else {
      charCount.parentElement.classList.remove("limit-near");
    }
  }

  // Show Alert
  function showAlert(title, message, type = "error") {
    alertBox.className = `alert alert-${type}`;
    alertTitle.textContent = title;
    alertMessage.innerHTML = message;
    alertBox.classList.remove("hidden");
    alertBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  // Hide Alert
  function hideAlert() {
    alertBox.classList.add("hidden");
  }

  // Populate Sample
  sampleButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const sampleKey = btn.getAttribute("data-sample");
      const lang = btn.getAttribute("data-lang") || "english";

      if (SAMPLES[sampleKey]) {
        messageInput.value = SAMPLES[sampleKey];
        languageSelect.value = lang;
        updateCharCount();
        hideAlert();
        resultsSection.classList.add("hidden");
        messageInput.focus();
      }
    });
  });

  // Clear Input
  clearBtn.addEventListener("click", () => {
    messageInput.value = "";
    updateCharCount();
    hideAlert();
    resultsSection.classList.add("hidden");
    messageInput.focus();
  });

  // Alert Close
  alertClose.addEventListener("click", hideAlert);

  // Character Count Listener
  messageInput.addEventListener("input", updateCharCount);

  // Keyboard shortcut: Ctrl+Enter / Cmd+Enter to analyze
  messageInput.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      analyzeBtn.click();
    }
  });

  // Render Analysis Results
  function renderResults(analysis, language) {
    const risk = (analysis.riskLevel || "UNKNOWN").toUpperCase();

    // Reset card classes
    riskCard.className = "risk-card";

    let subtitle = "Inconclusive Analysis";
    if (risk === "HIGH") {
      riskCard.classList.add("risk-high");
      subtitle = language === "telugu" ? "తీవ్రమైన ప్రమాదం (High Scam Threat)" : "Severe Threat Detected";
    } else if (risk === "MEDIUM") {
      riskCard.classList.add("risk-med");
      subtitle = language === "telugu" ? "అనుమానాస్పద సంకేతాలు (Suspicious Indicators)" : "Suspicious Pattern Detected";
    } else if (risk === "LOW") {
      riskCard.classList.add("risk-low");
      subtitle = language === "telugu" ? "తక్కువ ప్రమాదం (Appears Legitimate)" : "Low Probability of Scam";
    } else {
      riskCard.classList.add("risk-unk");
      subtitle = language === "telugu" ? "మిశ్రమ లేదా అనిశ్చిత ఆధారాలు" : "Mixed or Inconclusive Evidence";
    }

    riskBadge.textContent = `${risk} RISK`;
    riskSubtitle.textContent = subtitle;
    resultLanguageTag.textContent = `Language: ${language === "telugu" ? "తెలుగు (Telugu)" : "English"}`;
    riskSummaryText.textContent = analysis.summary || "No summary provided by the model.";

    // Render Indicators
    indicatorsList.innerHTML = "";
    const indicators = Array.isArray(analysis.suspiciousIndicators) ? analysis.suspiciousIndicators : [];
    if (indicators.length === 0) {
      const li = document.createElement("li");
      li.textContent = language === "telugu"
        ? "ప్రత్యేక అనుమానాస్పద సంకేతాలేవీ కనిపించలేదు."
        : "No explicit suspicious indicators flagged.";
      indicatorsList.appendChild(li);
    } else {
      indicators.forEach((item) => {
        const li = document.createElement("li");
        li.textContent = item;
        indicatorsList.appendChild(li);
      });
    }

    // Render Advice
    adviceList.innerHTML = "";
    const advice = Array.isArray(analysis.safetyAdvice) ? analysis.safetyAdvice : [];
    if (advice.length === 0) {
      const li = document.createElement("li");
      li.textContent = language === "telugu"
        ? "ఎల్లప్పుడూ అధికారిక వెబ్‌సైట్ లేదా ఫోన్ నంబర్ ద్వారా మాత్రమే ధృవీకరించుకోండి."
        : "Always verify directly through official channels before taking action.";
      adviceList.appendChild(li);
    } else {
      advice.forEach((item) => {
        const li = document.createElement("li");
        li.textContent = item;
        adviceList.appendChild(li);
      });
    }

    // Disclaimer
    disclaimerText.textContent = analysis.disclaimer || "This is an AI estimate, not proof. ScamShield cannot confirm that a URL is malicious without independent reputation data.";

    resultsSection.classList.remove("hidden");
    resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  // Main Analyze Handler
  analyzeBtn.addEventListener("click", async () => {
    const rawMessage = messageInput.value.trim();
    const language = languageSelect.value;

    if (!rawMessage) {
      showAlert("Message Required", "Please paste or type a suspicious message to analyze.", "warning");
      messageInput.focus();
      return;
    }

    if (rawMessage.length > 10000) {
      showAlert("Message Too Long", "Message exceeds 10,000 characters. Please shorten it.", "error");
      return;
    }

    // Loading State
    hideAlert();
    resultsSection.classList.add("hidden");
    analyzeBtn.disabled = true;
    analyzeBtn.classList.add("loading");
    analyzeBtnText.textContent = language === "telugu" ? "విశ్లేషిస్తోంది..." : "Analyzing with Gemma AI...";

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: rawMessage,
          language: language,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        if (data.code === "API_KEY_MISSING") {
          showAlert(
            "Gemini API Key Required",
            `<strong>API Key is not configured yet.</strong><br>
             1. Open <code>C:\\Users\\Karthik\\OneDrive\\Desktop\\scamshield\\.env</code> on your computer.<br>
             2. Replace <code>your_actual_key_goes_here</code> with your real key from Google AI Studio.<br>
             3. Restart the server with <code>npm start</code>.`,
            "warning"
          );
        } else if (data.code === "INVALID_API_KEY") {
          showAlert(
            "Invalid API Key",
            "The configured Gemini API key was rejected by Google AI Studio. Please verify your key in <code>.env</code>.",
            "error"
          );
        } else if (data.code === "QUOTA_EXCEEDED") {
          showAlert(
            "Quota Exceeded",
            "The Gemini API rate limit or quota has been reached. Please wait a minute and try again.",
            "warning"
          );
        } else {
          showAlert(
            "Analysis Error",
            escapeHtml(data.error || "An unexpected error occurred while analyzing the message."),
            "error"
          );
        }
        return;
      }

      if (data.analysis) {
        renderResults(data.analysis, data.language || language);
      } else {
        showAlert("Unexpected Output", "The server returned a response with missing analysis data.", "error");
      }
    } catch (err) {
      showAlert(
        "Network Error",
        "Could not reach the ScamShield backend. Make sure the server is running on port 3000.",
        "error"
      );
    } finally {
      analyzeBtn.disabled = false;
      analyzeBtn.classList.remove("loading");
      analyzeBtnText.textContent = "Analyze Message";
    }
  });

  function escapeHtml(str) {
    if (!str) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // Initial health check
  checkHealth();
});
