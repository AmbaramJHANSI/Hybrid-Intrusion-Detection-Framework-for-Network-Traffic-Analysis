let attackChart = null;
let featureChart = null;
let performanceChart = null;
let anomalyChart = null;

document.addEventListener("DOMContentLoaded", loadDashboard);

async function loadDashboard() {
  const insightBox = document.getElementById("insightList");
  try {
    const response = await fetch("/analyze", { cache: "no-store" });
    if (!response.ok) throw new Error(`API returned HTTP ${response.status}`);
    const data = await response.json();
    if (data.status !== "success") throw new Error(data.message || "Analysis failed");

    populateKPI(data);
    populateDataset(data);
    populateThreat(data);
    populateAnomaly(data);
    populateAnomalyEvaluation(data);
    populateConfusion(data);
    populateClassification(data);
    populatePerformance(data);
    generateInsights(data);
    document.getElementById("apiResponse").textContent = JSON.stringify(data, null, 2);
  } catch (error) {
    console.error("Dashboard load failed:", error);
    insightBox.innerHTML = "";
    const alert = document.createElement("div");
    alert.className = "alert alert-danger";
    alert.textContent = `Unable to load dashboard data: ${error.message}`;
    insightBox.appendChild(alert);
    const body = document.querySelector("#anomalyTable tbody");
    if (body) body.innerHTML = '<tr><td colspan="3">Anomaly results unavailable.</td></tr>';
  }
}

function populateKPI(data) {
  setText("accuracy", pct(data.ml_detection?.accuracy));
  setText("riskLevel", data.signature_detection?.risk_level ?? "--");
  setText("attackCount", data.signature_detection?.attacks_detected ?? "--");
  setText("executionTime", formatExecutionTime(data.performance));
  const generatedAt = data.metadata?.generated_at;
  const generatedAtElement = document.getElementById("analysisGeneratedAt");
  if (generatedAtElement) {
    const generatedAtDate = new Date(generatedAt);
    if (Number.isNaN(generatedAtDate.getTime())) {
      generatedAtElement.textContent = "--";
      generatedAtElement.removeAttribute("datetime");
    } else {
      generatedAtElement.textContent = generatedAtDate.toLocaleString();
      generatedAtElement.dateTime = generatedAtDate.toISOString();
    }
  }
  setText("modelBadge", data.metadata?.classification_model ?? "Random Forest");
  setText("datasetBadge", data.metadata?.dataset ?? data.dataset?.name ?? "NSL-KDD");
  setText("apiVersion", `API v${data.metadata?.api_version ?? "3.0"}`);
}

function populateDataset(data) {
  setText("datasetName", data.dataset?.name ?? "--");
  setText("samples", data.dataset?.samples ?? "--");
  setText("features", data.dataset?.features ?? "--");
  setText("training", data.dataset?.training_samples ?? data.ml_detection?.training_samples ?? "--");
  setText("testing", data.dataset?.testing_samples ?? data.ml_detection?.testing_samples ?? "--");
}

function populateThreat(data) {
  const sig = data.signature_detection ?? {};
  setText("summaryRisk", sig.risk_level ?? "--");
  setText("attackPercent", `${sig.attack_percentage ?? "--"}%`);
  setText("topAttack", sig.most_frequent_attack ?? "--");
  setText("rulesTriggered", sig.rules_triggered ?? "--");

  const distribution = sig.attack_distribution ?? {};
  const distributionTotal = Object.values(distribution)
    .reduce((total, count) => total + Number(count), 0);
  if (attackChart) attackChart.destroy();
  attackChart = new Chart(document.getElementById("attackChart"), {
    type: "pie",
    data: { labels: Object.keys(distribution), datasets: [{ data: Object.values(distribution) }] },
    options: {
      responsive: true,
      plugins: {
        legend: { labels: { color: "#eaf1fb" } },
        tooltip: {
          callbacks: {
            label: context => {
              const count = Number(context.raw);
              const percentage = distributionTotal
                ? (count / distributionTotal * 100).toFixed(2)
                : "0.00";
              return `${context.label}: ${count} (${percentage}%)`;
            }
          }
        }
      }
    }
  });

  const features = data.ml_detection?.top_features ?? [];
  if (featureChart) featureChart.destroy();
  featureChart = new Chart(document.getElementById("featureChart"), {
    type: "bar",
    data: {
      labels: features.map(item => item.feature),
      datasets: [{
        label: "Feature importance (%)",
        data: features.map(item => Number(item.importance_percent)),
        backgroundColor: "rgba(56, 189, 248, 0.72)",
        borderColor: "#38bdf8",
        borderWidth: 1,
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      indexAxis: "y",
      scales: {
        x: {
          beginAtZero: true,
          max: 100,
          ticks: {
            color: "#eaf1fb",
            callback: value => `${value}%`
          },
          grid: { color: "rgba(148, 163, 184, 0.18)" }
        },
        y: {
          ticks: { color: "#eaf1fb" },
          grid: { display: false }
        }
      },
      plugins: {
        legend: { labels: { color: "#eaf1fb" } },
        tooltip: {
          callbacks: {
            label: context => `${context.dataset.label}: ${Number(context.raw).toFixed(2)}%`
          }
        }
      }
    }
  });
}

function populateAnomaly(data) {
  const result = data.anomaly_detection;
  if (!result) {
    setText("anomalySamples", "N/A");
    setText("anomalyCount", "N/A");
    setText("anomalyPercent", "N/A");
    const body = document.querySelector("#anomalyTable tbody");
    body.replaceChildren();
    const row = body.insertRow();
    const cell = row.insertCell(); cell.colSpan = 3; cell.textContent = "This API response does not contain anomaly_detection results.";
    return;
  }

  setText("anomalySamples", result.samples_analyzed ?? 0);
  setText("anomalyCount", result.anomalies_detected ?? 0);
  setText("anomalyPercent", `${Number(result.anomaly_percentage ?? 0).toFixed(2)}%`);

  if (anomalyChart) anomalyChart.destroy();
  anomalyChart = new Chart(document.getElementById("anomalyChart"), {
    type: "doughnut",
    data: {
      labels: ["Anomalies flagged", "Normal patterns"],
      datasets: [{ data: [Number(result.anomalies_detected ?? 0), Number(result.normal_patterns ?? 0)] }]
    },
    options: { responsive: true, plugins: { legend: { position: "bottom", labels: { color: "white" } } } }
  });

  const tbody = document.querySelector("#anomalyTable tbody");
  tbody.replaceChildren();
  const flagged = Array.isArray(result.flagged_records) ? result.flagged_records : [];
  if (flagged.length === 0) {
    const row = tbody.insertRow();
    const cell = row.insertCell(); cell.colSpan = 3; cell.textContent = "No records were flagged in this run.";
    return;
  }
  flagged.forEach(item => {
    const row = tbody.insertRow();
    row.insertCell().textContent = item.test_record_index;
    const resultCell = row.insertCell();
    const badge = document.createElement("span");
    badge.className = "badge rounded-pill bg-danger";
    badge.textContent = "Anomaly flagged";
    resultCell.appendChild(badge);
    row.insertCell().textContent = Number(item.anomaly_score).toFixed(6);
  });
}


function populateAnomalyEvaluation(data) {
  const result = data.anomaly_detection ?? {};
  // Support the current API shape: anomaly_detection.evaluation.
  // Also tolerate evaluation stored at the response root.
  const evaluation = result.evaluation ?? data.anomaly_evaluation ?? null;
  const status = document.getElementById("anomalyEvaluationStatus");
  const notes = document.getElementById("ifEvaluationNotes");

  if (!evaluation) {
    ["ifAccuracy", "ifPrecision", "ifRecall", "ifF1"].forEach(id => setText(id, "--"));
    ["ifTN", "ifFP", "ifFN", "ifTP"].forEach(id => setText(id, "--"));
    if (status) status.textContent =
      "Evaluation data is not present in this API response. Add anomaly_detection.evaluation in backend/app.py; values are not estimated or hardcoded.";
    if (notes) {
      notes.replaceChildren();
      const li = document.createElement("li");
      li.className = "list-group-item";
      li.textContent = "No ground-truth evaluation metrics were returned by the API.";
      notes.appendChild(li);
    }
    return;
  }

  const metric = value => Number.isFinite(Number(value)) ? pct(value) : "--";
  setText("ifAccuracy", metric(evaluation.accuracy));
  setText("ifPrecision", metric(evaluation.precision));
  setText("ifRecall", metric(evaluation.recall));
  setText("ifF1", metric(evaluation.f1_score));

  const cm = evaluation.confusion_matrix ?? {};
  const matrix = cm.matrix;
  if (Array.isArray(matrix) && matrix.length === 2 && matrix.every(row => Array.isArray(row) && row.length === 2)) {
    setText("ifTN", matrix[0][0]);
    setText("ifFP", matrix[0][1]);
    setText("ifFN", matrix[1][0]);
    setText("ifTP", matrix[1][1]);
  } else {
    setText("ifTN", cm.true_negative ?? evaluation.true_negative ?? "--");
    setText("ifFP", cm.false_positive ?? evaluation.false_positive ?? "--");
    setText("ifFN", cm.false_negative ?? evaluation.false_negative ?? "--");
    setText("ifTP", cm.true_positive ?? evaluation.true_positive ?? "--");
  }

  if (status) {
    const count = evaluation.samples_evaluated ?? evaluation.testing_samples ?? data.dataset?.testing_samples ?? "--";
    status.textContent = `Ground-truth comparison completed for ${count} test records.`;
  }

  if (notes) {
    notes.replaceChildren();
    const items = [
      `True positives (attacks flagged): ${cm.true_positive ?? evaluation.true_positive ?? "--"}`,
      `True negatives (normal records not flagged): ${cm.true_negative ?? evaluation.true_negative ?? "--"}`,
      `False positives (normal records flagged): ${cm.false_positive ?? evaluation.false_positive ?? "--"}`,
      `False negatives (attacks missed): ${cm.false_negative ?? evaluation.false_negative ?? "--"}`
    ];
    items.forEach(text => {
      const li = document.createElement("li");
      li.className = "list-group-item";
      li.textContent = text;
      notes.appendChild(li);
    });
  }
}

function populateConfusion(data) {
  const c = data.ml_detection?.confusion_matrix ?? {};
  const matrix = c.matrix;
  const labels = c.labels ?? data.ml_detection?.class_order ?? [];
  if (Array.isArray(matrix) && matrix.length === 2 && matrix.every(row => Array.isArray(row) && row.length === 2)) {
    setText("tn", matrix[0][0]);
    setText("fp", matrix[0][1]);
    setText("fn", matrix[1][0]);
    setText("tp", matrix[1][1]);
  } else {
    setText("tn", c.true_negative ?? "--");
    setText("fp", c.false_positive ?? "--");
    setText("fn", c.false_negative ?? "--");
    setText("tp", c.true_positive ?? "--");
  }

  if (labels.length === 2) {
    setText("predictedNormalLabel", `Predicted ${labels[0]}`);
    setText("predictedAttackLabel", `Predicted ${labels[1]}`);
    setText("actualNormalLabel", `Actual ${labels[0]}`);
    setText("actualAttackLabel", `Actual ${labels[1]}`);
  }
}

function populateClassification(data) {
  const tbody = document.querySelector("#classificationTable tbody");
  tbody.replaceChildren();
  const report = data.ml_detection?.classification_report ?? {};
  const classOrder = data.ml_detection?.class_order ?? [];
  const orderedKeys = [
    ...classOrder,
    "macro avg",
    "weighted avg"
  ].filter(key => Object.hasOwn(report, key));
  orderedKeys.forEach(key => {
    const metrics = report[key];
    if (!metrics || typeof metrics !== "object" || !("precision" in metrics)) return;
    const row = tbody.insertRow();
    [key, num(metrics.precision), num(metrics.recall), num(metrics["f1-score"]), metrics.support ?? "--"]
      .forEach(value => { row.insertCell().textContent = value; });
  });
}

function populatePerformance(data) {
  const perf = data.performance ?? {};
  const labels = ["Dataset loading", "Data cleaning", "Feature encoding", "Signature detection", "RF training", "RF prediction", "IF training", "IF prediction"];
  const values = [perf.dataset_loading_ms, perf.cleaning_ms, perf.encoding_ms, perf.signature_detection_ms,
    perf.model_training_ms, perf.model_prediction_ms, perf.anomaly_training_ms, perf.anomaly_prediction_ms];
  if (performanceChart) performanceChart.destroy();
  performanceChart = new Chart(document.getElementById("performanceChart"), {
    type: "bar",
    data: { labels, datasets: [{ label: "Single-run time (ms)", data: values.map(value => Number(value ?? 0)) }] },
    options: { responsive: true, scales: { x: { ticks: { color: "white" } }, y: { beginAtZero: true, ticks: { color: "white" } } }, plugins: { legend: { labels: { color: "white" } } } }
  });
}

function generateInsights(data) {
  const box = document.getElementById("insightList");
  box.replaceChildren();
  const list = document.createElement("ul");
  list.className = "list-group list-group-flush";
  const firstFeature = data.ml_detection?.top_features?.[0]?.feature ?? "--";
  const anomaly = data.anomaly_detection;
  const items = [
    `Random Forest test accuracy: ${pct(data.ml_detection?.accuracy)}`,
    `Signature module risk level: ${data.signature_detection?.risk_level ?? "--"}`,
    `Signature detections: ${data.signature_detection?.attacks_detected ?? "--"}`,
    `Isolation Forest anomalies flagged: ${anomaly?.anomalies_detected ?? "not available"}${anomaly ? ` (${Number(anomaly.anomaly_percentage).toFixed(2)}% of test records)` : ""}`,
    `Highest-ranked Random Forest feature: ${firstFeature}`,
    `Total API execution time: ${formatExecutionTime(data.performance)}`
  ];
  items.forEach(text => { const li = document.createElement("li"); li.className = "list-group-item"; li.textContent = text; list.appendChild(li); });
  box.appendChild(list);
}

function setText(id, value) {
  const element = document.getElementById(id);
  if (element) element.textContent = value;
}
function formatExecutionTime(performance) {
  const total = Number(performance?.total_execution_ms);
  return Number.isFinite(total) ? `${total.toFixed(1)} ms` : "--";
}
function pct(value) { return Number.isFinite(Number(value)) ? `${(Number(value) * 100).toFixed(2)}%` : "--"; }
function num(value) { return value === undefined || value === null ? "-" : Number(value).toFixed(3); }
