document.addEventListener("DOMContentLoaded", () => {
  const scanBtn = document.getElementById("scan-btn");
  const urlInput = document.getElementById("url-input");
  const resultsArea = document.getElementById("results-area");
  const predictionText = document.getElementById("prediction-text");
  const confidenceText = document.getElementById("confidence-text");
  const errorMsg = document.getElementById("error-msg");

  const btnText = document.getElementById("btn-text");
  const btnSpinner = document.getElementById("btn-spinner");

  const themeToggle = document.getElementById("theme-toggle");
  const mainBody = document.getElementById("main-body");

  const safeActionArea = document.getElementById("safe-action-area");
  const safeBio = document.getElementById("safe-bio");
  const safeLinkBtn = document.getElementById("safe-link-btn");

  const suggestionBox = document.getElementById("suggestion-box");
  const suggestionText = document.getElementById("suggestion-text");
  const suggestionLinkContainer = document.getElementById(
    "suggestion-link-container",
  );
  const suggestionLink = document.getElementById("suggestion-link");

  // Onboarding Modal
  const onboardingModal = document.getElementById("onboarding-modal");
  const closeOnboarding = document.getElementById("close-onboarding");
  const openAboutBtn = document.getElementById("open-about-btn");

  // Community feedback controls
  const feedbackPanel = document.getElementById("feedback-panel");
  const feedbackDescription = document.getElementById("feedback-description");
  const feedbackSafeBtn = document.getElementById("feedback-safe-btn");
  const feedbackPhishBtn = document.getElementById("feedback-phish-btn");
  const feedbackNote = document.getElementById("feedback-note");
  const feedbackStatus = document.getElementById("feedback-status");

  let latestScanData = null;

  function openOnboarding() {
    onboardingModal.classList.remove("hidden");
  }

  function closeOnboardingModal() {
    onboardingModal.classList.add("hidden");
    localStorage.setItem("secops_visited", "true");
  }

  if (!localStorage.getItem("secops_visited")) {
    openOnboarding();
  }

  closeOnboarding.addEventListener("click", closeOnboardingModal);
  openAboutBtn.addEventListener("click", openOnboarding);

  let doughnutChart = null;
  let barChart = null;
  let isDarkMode = true;

  const sunIcon = document.getElementById("theme-icon-sun");
  const moonIcon = document.getElementById("theme-icon-moon");

  themeToggle.addEventListener("click", () => {
    isDarkMode = !isDarkMode;
    if (isDarkMode) {
      mainBody.classList.remove("light-mode");
      sunIcon.classList.add("hidden");
      moonIcon.classList.remove("hidden");
    } else {
      mainBody.classList.add("light-mode");
      moonIcon.classList.add("hidden");
      sunIcon.classList.remove("hidden");
    }

    // Refresh chart colors after theme switch so legend text remains readable.
    if (latestScanData && typeof latestScanData.confidence === "number") {
      renderDoughnutChart(latestScanData.prediction, latestScanData.confidence);
    }
  });

  urlInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      scanBtn.click();
    }
  });

  scanBtn.addEventListener("click", async () => {
    const url = urlInput.value.trim();

    if (!url) {
      showError("Please enter a valid URL to scan.");
      return;
    }

    errorMsg.classList.add("hidden");
    resultsArea.classList.add("hidden");
    btnText.textContent = "Scanning...";
    btnSpinner.classList.remove("hidden");
    scanBtn.disabled = true;

    try {
      const response = await fetch("/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();

      if (!response.ok) {
        // Reset colors to error red
        errorMsg.classList.remove("text-amber-500");
        errorMsg.classList.add("text-red-400");
        showError(
          data.error || "System Error: Unable to complete URL analysis.",
        );
        return;
      }

      // Hide simple error text since we'll use the big warning box instead
      errorMsg.classList.add("hidden");

      renderResults(data);
    } catch (error) {
      console.error("Error fetching prediction:", error);
      showError("Server error or network failure.");
    } finally {
      btnText.textContent = "Scan Link";
      btnSpinner.classList.add("hidden");
      scanBtn.disabled = false;
    }
  });

  function showError(message) {
    errorMsg.textContent = message;
    errorMsg.classList.remove("hidden");
  }

  function renderResults(data) {
    resultsArea.classList.remove("hidden");
    latestScanData = data;

    if (data.normalized_url) {
      urlInput.value = data.normalized_url;
    }

    // Handle suggestions, typosquatting warnings, and offline alerts
    const suggestionTitle = document.getElementById("suggestion-title");

    if (data.suggested_site) {
      suggestionBox.classList.remove("hidden");

      let contextMsg = "";
      if (data.prediction === "Phishing" || data.prediction === "Caution") {
        suggestionTitle.textContent = "Security Warning: Brand Impersonation";
        contextMsg =
          "This domain appears to be severely typosquatted or using malicious characters to trick you.";

        // Make the box red instead of amber
        suggestionBox.classList.remove("bg-amber-500/10", "border-amber-500");
        suggestionBox.classList.add("bg-red-500/10", "border-red-500");
        suggestionTitle.parentElement.classList.remove("text-amber-500");
        suggestionTitle.parentElement.classList.add("text-red-500");
      } else {
        suggestionTitle.textContent = "Site Offline or Unreachable";
        contextMsg =
          data.ping_warning ||
          "This URL does not appear to exist or might be offline.";

        suggestionBox.classList.remove("bg-red-500/10", "border-red-500");
        suggestionBox.classList.add("bg-amber-500/10", "border-amber-500");
        suggestionTitle.parentElement.classList.remove("text-red-500");
        suggestionTitle.parentElement.classList.add("text-amber-500");
      }

      suggestionText.textContent = contextMsg;
      suggestionLinkContainer.classList.remove("hidden");
      suggestionLink.href = data.suggested_site.url;
      suggestionLink.querySelector("span").textContent =
        `Go to Verified ${data.suggested_site.name} Instead`;
    } else if (!data.is_live && data.ping_warning) {
      suggestionBox.classList.remove("hidden");
      suggestionBox.classList.remove("bg-red-500/10", "border-red-500");
      suggestionBox.classList.add("bg-amber-500/10", "border-amber-500");
      suggestionTitle.parentElement.classList.remove("text-red-500");
      suggestionTitle.parentElement.classList.add("text-amber-500");

      suggestionTitle.textContent = "Site Offline or Unreachable";
      suggestionText.textContent = data.ping_warning;
      suggestionLinkContainer.classList.add("hidden");
    } else {
      suggestionBox.classList.add("hidden");
    }

    const isPhishing = data.prediction === "Phishing";
    const isCaution = data.prediction === "Caution";
    predictionText.textContent = data.prediction;
    confidenceText.textContent = `Confidence: ${data.confidence}%`;

    predictionText.className =
      "text-5xl font-extrabold mt-4 uppercase transition-all drop-shadow-[0_0_15px_rgba(255,255,255,0.5)]";

    if (isPhishing) {
      predictionText.classList.add(
        "text-red-500",
        "drop-shadow-[0_0_15px_rgba(239,68,68,0.8)]",
      );
      safeActionArea.classList.add("hidden");
    } else if (isCaution) {
      predictionText.classList.add(
        "text-amber-500",
        "drop-shadow-[0_0_12px_rgba(217,137,0,0.55)]",
      );
      safeActionArea.classList.add("hidden");
    } else {
      predictionText.classList.add(
        "text-green-400",
        "drop-shadow-[0_0_15px_rgba(74,222,128,0.8)]",
      );

      if (data.bio && data.safe_link) {
        safeBio.textContent = data.bio;
        safeLinkBtn.href = data.safe_link;
        safeActionArea.classList.remove("hidden");
      }
    }

    const threatSection = document.getElementById("threat-analysis-section");
    const threatList = document.getElementById("threat-list");

    if (data.threat_summary && data.threat_summary.length > 0) {
      threatSection.classList.remove("hidden");
      threatList.innerHTML = "";

      data.threat_summary.forEach((t) => {
        const li = document.createElement("li");
        li.className = "flex items-start text-slate-300";

        let iconSvg = "";
        let cleanText = t;

        if (t.startsWith("[PASS]")) {
          cleanText = t.replace("[PASS]", "").trim();
          iconSvg = `<svg class="w-5 h-5 text-green-400 mt-0.5 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>`;
        } else if (t.startsWith("[WARN]")) {
          cleanText = t.replace("[WARN]", "").trim();
          iconSvg = `<svg class="w-5 h-5 text-amber-500 mt-0.5 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>`;
        } else if (t.startsWith("[FAIL]")) {
          cleanText = t.replace("[FAIL]", "").trim();
          iconSvg = `<svg class="w-5 h-5 text-red-500 mt-0.5 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>`;
        } else {
          // Fallback just in case
          iconSvg = `<svg class="w-5 h-5 text-cyan-400 mt-0.5 mr-2 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>`;
        }

        li.innerHTML = `${iconSvg} <span class="pt-0.5">${cleanText}</span>`;
        threatList.appendChild(li);
      });
    } else if (threatSection) {
      threatSection.classList.add("hidden");
    }

    renderDoughnutChart(data.prediction, data.confidence);

    const shouldRequestFeedback = data.model_uncertain || !data.is_known_domain;
    if (shouldRequestFeedback) {
      feedbackPanel.classList.remove("hidden");
      feedbackStatus.textContent = "";
      feedbackNote.value = "";

      if (data.model_uncertain) {
        feedbackDescription.textContent =
          "This result is in the uncertainty zone. Your label helps our review pipeline validate emerging domains.";
      } else {
        feedbackDescription.textContent =
          "This domain is not in our known registry yet. Community feedback helps us review new websites safely.";
      }
    } else {
      feedbackPanel.classList.add("hidden");
    }
  }

  async function submitFeedback(userLabel) {
    if (!latestScanData) return;

    feedbackStatus.textContent = "Saving feedback...";
    feedbackStatus.className = "text-xs mt-2 text-slate-400";

    const payload = {
      url: latestScanData.normalized_url || urlInput.value.trim(),
      user_label: userLabel,
      note: feedbackNote.value.trim(),
      model_prediction: latestScanData.prediction,
      model_confidence: latestScanData.confidence,
      is_known_domain: latestScanData.is_known_domain,
      model_uncertain: latestScanData.model_uncertain,
    };

    try {
      const response = await fetch("/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.error || "Unable to save feedback.");
      }

      feedbackStatus.textContent =
        "Thanks. Your feedback was queued for review.";
      feedbackStatus.className = "text-xs mt-2 text-green-400";
    } catch (err) {
      feedbackStatus.textContent =
        err.message || "Feedback failed to save. Please try again.";
      feedbackStatus.className = "text-xs mt-2 text-red-400";
    }
  }

  feedbackSafeBtn.addEventListener("click", () => submitFeedback("safe"));
  feedbackPhishBtn.addEventListener("click", () => submitFeedback("phishing"));

  function renderDoughnutChart(prediction, confidence) {
    const ctx = document.getElementById("probability-chart").getContext("2d");

    if (doughnutChart) doughnutChart.destroy();

    let phishingProb = 0;
    let safeProb = 0;
    let cautionProb = 0;

    if (prediction === "Phishing") {
      phishingProb = confidence;
      safeProb = 100 - confidence;
      cautionProb = 0;
    } else if (prediction === "Safe") {
      phishingProb = 100 - confidence;
      safeProb = confidence;
      cautionProb = 0;
    } else {
      // For caution, center the main probability on amber and split the remainder.
      cautionProb = confidence;
      const remainder = Math.max(0, 100 - confidence);
      phishingProb = remainder / 2;
      safeProb = remainder / 2;
    }

    const legendLabelColor = isDarkMode ? "#e2e8f0" : "#0f172a";

    doughnutChart = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["Phishing", "Safe", "Caution"],
        datasets: [
          {
            data: [phishingProb, safeProb, cautionProb],
            backgroundColor: ["#ef4444", "#4ade80", "#d18b00"],
            borderWidth: 0,
            hoverOffset: 4,
          },
        ],
      },
      options: {
        responsive: true,
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color: legendLabelColor,
              font: { size: 14, weight: "bold" },
              padding: 15,
              boxWidth: 18,
            },
          },
        },
      },
    });
  }
});

const cyberTips = [
  'Beware of typos in domains like "l" instead of "I".',
  "If it sounds too good to be true, it’s usually phishing!",
  "Hover over links before clicking to see the real destination.",
  "Banks will never ask for your password via email.",
  "Zero-day phishing sites often use HTTP instead of HTTPS.",
  'Hackers use urgency like "Account Suspended" to create panic!',
  "Always check the sender email address closely.",
  "Unexpected attachments? Think twice before opening.",
  "Multi-Factor Authentication (MFA) protects stolen passwords.",
  "Public Wi-Fi + generic HTTP = Bad Day. Use a VPN!",
];

function rotateTip() {
  const tipEl = document.getElementById("random-cyber-tip");
  if (tipEl) {
    const randomTip = cyberTips[Math.floor(Math.random() * cyberTips.length)];
    tipEl.innerText = "💡 Tip: " + randomTip;
  }
}

setInterval(rotateTip, 5000);
document.addEventListener("DOMContentLoaded", rotateTip);
