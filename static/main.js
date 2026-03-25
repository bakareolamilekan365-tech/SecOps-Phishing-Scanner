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
  });

  urlInput.addEventListener("blur", () => {
    let val = urlInput.value.trim();
    if (val && !val.startsWith("http://") && !val.startsWith("https://")) {
      urlInput.value = "https://" + val;
    }
  });

  urlInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      scanBtn.click();
    }
  });

  scanBtn.addEventListener("click", async () => {
    let url = urlInput.value.trim();

    if (url && !url.startsWith("http://") && !url.startsWith("https://")) {
      url = "https://" + url;
      urlInput.value = url;
    }

    if (!url) {
      showError("Hold on! You need to drop a link in there first.");
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
          data.error || "Failed to detect phishing. Is the model trained?",
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

    // Handle the offline / suggestion block
    if (!data.is_live) {
      suggestionBox.classList.remove("hidden");
      suggestionText.textContent =
        data.ping_warning ||
        "This URL does not appear to exist or might be offline.";

      // Do we have a brilliant brand typo suggestion?
      if (data.suggested_site) {
        suggestionLinkContainer.classList.remove("hidden");
        suggestionLink.href = data.suggested_site.url;
        // Find the inner span to just change the text, leave the arrow SVG alone
        suggestionLink.querySelector("span").textContent =
          `Go to ${data.suggested_site.name} Instead`;
      } else {
        suggestionLinkContainer.classList.add("hidden");
      }
    } else {
      // Is live, hide the warning box entirely
      suggestionBox.classList.add("hidden");
    }

    const isPhishing = data.prediction === "Phishing";
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

    renderDoughnutChart(isPhishing, data.confidence);
    renderBarChart(data.features);
  }

  function renderDoughnutChart(isPhishing, confidence) {
    const ctx = document.getElementById("probability-chart").getContext("2d");

    if (doughnutChart) doughnutChart.destroy();

    const phishingProb = isPhishing ? confidence : 100 - confidence;
    const safeProb = isPhishing ? 100 - confidence : confidence;

    doughnutChart = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["Phishing", "Safe"],
        datasets: [
          {
            data: [phishingProb, safeProb],
            backgroundColor: ["#ef4444", "#4ade80"],
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
            labels: { color: "#e2e8f0" },
          },
        },
      },
    });
  }

  function renderBarChart(features) {
    const ctx = document.getElementById("features-chart").getContext("2d");

    if (barChart) barChart.destroy();

    barChart = new Chart(ctx, {
      type: "bar",
      data: {
        labels: Object.keys(features),
        datasets: [
          {
            label: "Feature Counts/Flags",
            data: Object.values(features),
            backgroundColor: "#06b6d4",
            borderRadius: 4,
          },
        ],
      },
      options: {
        indexAxis: "y",
        responsive: true,
        scales: {
          x: {
            beginAtZero: true,
            ticks: { color: "#94a3b8" },
            grid: { color: "#334155" },
          },
          y: {
            ticks: { color: "#e2e8f0" },
            grid: { display: false },
          },
        },
        plugins: {
          legend: { display: false },
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
