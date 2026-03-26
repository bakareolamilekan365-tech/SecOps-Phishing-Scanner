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
  const suggestionLinkContainer = document.getElementById("suggestion-link-container");
  const suggestionLink = document.getElementById("suggestion-link");
  const threatList = document.getElementById("threat-list");

  let doughnutChart = null;
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

  urlInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      scanBtn.click();
    }
  });

  scanBtn.addEventListener("click", async () => {
    let url = urlInput.value.trim();

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
        errorMsg.classList.remove("text-amber-500");
        errorMsg.classList.add("text-red-400");
        showError(data.error || "Failed to detect phishing. Is the model trained?");
        return;
      }

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

    if (!data.is_live && data.ping_warning) {
      suggestionBox.classList.remove("hidden");
      suggestionBox.className = "mt-6 p-4 rounded-lg bg-red-900/40 border border-red-500/50 flex flex-col sm:flex-row gap-4 items-center";
      suggestionText.textContent = data.ping_warning;

      if (data.suggested_site) {
        suggestionLinkContainer.classList.remove("hidden");
        suggestionLink.href = data.suggested_site.url;
        suggestionLink.querySelector("span").textContent = `Go to ${data.suggested_site.name} Instead`;
      } else {
        suggestionLinkContainer.classList.add("hidden");
      }
    } else if (data.prediction === "Caution") {
      suggestionBox.classList.remove("hidden");
      // Change styling to amber warning for Caution
      suggestionBox.className = "mt-6 p-4 rounded-lg bg-amber-900/40 border border-amber-500/50 flex flex-col sm:flex-row gap-4 items-center";
      suggestionText.textContent = "Warning: This domain is similar to a known brand. Ensure this is your intended destination.";
      
      if (data.suggested_site) {
        suggestionLinkContainer.classList.remove("hidden");
        suggestionLink.href = data.suggested_site.url;
        suggestionLink.className = "flex items-center gap-2 bg-amber-500/20 hover:bg-amber-500/40 text-amber-300 font-semibold py-2 px-4 rounded-lg transition-colors whitespace-nowrap border border-amber-500/30";
        suggestionLink.querySelector("span").textContent = `Go to Official ${data.suggested_site.name}`;
      } else {
        suggestionLinkContainer.classList.add("hidden");
      }
    } else {
      suggestionBox.classList.add("hidden");
    }

    predictionText.textContent = data.prediction;
    confidenceText.textContent = `Confidence: ${data.confidence}%`;

    predictionText.className = "text-5xl font-extrabold mt-4 uppercase transition-all drop-shadow-[0_0_15px_rgba(255,255,255,0.5)]";
    safeActionArea.classList.add("hidden");

    if (data.prediction === "Phishing") {
      predictionText.classList.add("text-red-500", "drop-shadow-[0_0_15px_rgba(239,68,68,0.8)]");
    } else if (data.prediction === "Caution") {
      predictionText.classList.add("text-amber-500", "drop-shadow-[0_0_15px_rgba(245,158,11,0.8)]");
    } else {
      predictionText.classList.add("text-green-400", "drop-shadow-[0_0_15px_rgba(74,222,128,0.8)]");
      if (data.bio && data.safe_link && data.is_live) {
        safeBio.textContent = data.bio;
        safeLinkBtn.href = data.safe_link;
        safeActionArea.classList.remove("hidden");
      }
    }

    renderThreatSummary(data.threat_summary);
    renderDoughnutChart(data.prediction, data.confidence);
  }

  function renderThreatSummary(threats) {
    threatList.innerHTML = "";
    if (threats && threats.length > 0) {
      threats.forEach(t => {
        const li = document.createElement("li");
        li.className = "flex items-start gap-2 mb-2 text-slate-300";
        li.innerHTML = `<svg class="w-5 h-5 text-indigo-400 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                        <span>${t}</span>`;
        threatList.appendChild(li);
      });
    }
  }

  function renderDoughnutChart(prediction, confidence) {
    const ctx = document.getElementById("probability-chart").getContext("2d");
    if (doughnutChart) doughnutChart.destroy();

    let chartColors = [];
    if (prediction === "Phishing") chartColors = ["#ef4444", "#1e293b"];
    else if (prediction === "Caution") chartColors = ["#f59e0b", "#1e293b"];
    else chartColors = ["#4ade80", "#1e293b"]; // Safe

    doughnutChart = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: [prediction, "Other"],
        datasets: [{
          data: [confidence, 100 - confidence],
          backgroundColor: chartColors,
          borderWidth: 0,
          hoverOffset: 4,
        }],
      },
      options: {
        responsive: true,
        plugins: {
          legend: { display: false }
        },
        cutout: "75%",
      },
    });
  }
});
