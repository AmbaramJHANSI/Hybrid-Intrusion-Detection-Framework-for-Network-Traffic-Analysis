/**
 * SOC (Security Operations Center) Dashboard
 * 
 * Production-grade dashboard for security analytics and threat detection.
 * Built with Vanilla JavaScript (ES6), Bootstrap 5, and Chart.js.
 * 
 * Architecture:
 * - Chart Management: Centralized instance storage for lifecycle management
 * - Data Flow: Fetch → Validate → Transform → Render
 * - Error Handling: Graceful degradation with user-friendly alerts
 * - Responsiveness: Bootstrap 5 grid system with Chart.js auto-scaling
 * 
 * @version 2.0
 * @author SOC Dashboard Team
 */

// ============================================================================
// CHART INSTANCE STORAGE & CONFIGURATION
// ============================================================================

/**
 * Stores Chart.js instances for proper lifecycle management.
 * Essential for destroying and recreating charts without memory leaks.
 */
const chartInstances = {
  attackChart: null,
  featureChart: null,
  performanceChart: null
};

/**
 * Global chart configuration constants.
 * Ensures consistency across all charts for visual cohesion.
 */
const CHART_CONFIG = {
  theme: {
    backgroundColor: 'rgba(59, 130, 246, 0.1)',
    borderColor: '#3b82f6',
    textColor: '#ffffff',
    gridColor: 'rgba(255, 255, 255, 0.1)',
    hoverBackgroundColor: 'rgba(59, 130, 246, 0.2)'
  },
  colors: {
    blue: '#3b82f6',
    green: '#10b981',
    red: '#ef4444',
    orange: '#f97316',
    purple: '#8b5cf6',
    cyan: '#06b6d4'
  },
  animation: {
    duration: 800,
    easing: 'easeInOutQuart'
  }
};

// ============================================================================
// DATA STORAGE
// ============================================================================

/**
 * Stores the most recent API response.
 * Used for insight generation and cached data access.
 */
let cachedDashboardData = null;

/**
 * Timestamp of last successful data fetch.
 * Used for "Last Updated" display.
 */
let lastUpdateTime = null;

// ============================================================================
// INITIALIZATION & LIFECYCLE
// ============================================================================

/**
 * Main initialization function.
 * Call this once on page load to bootstrap the dashboard.
 * 
 * Flow:
 * 1. Setup event listeners
 * 2. Fetch initial data
 * 3. Render all dashboard components
 * 4. Setup auto-refresh intervals
 */
const initializeDashboard = async () => {
  try {
    console.log('🚀 Initializing SOC Dashboard...');
    
    // Setup refresh button
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        refreshDashboard();
      });
    }
    
    // Initial data fetch and render
    await fetchDashboardData();
    
    console.log('✅ Dashboard initialization complete');
  } catch (error) {
    console.error('❌ Dashboard initialization failed:', error);
    showError('Failed to initialize dashboard. Please refresh the page.');
  }
};

/**
 * Refresh the entire dashboard with fresh data.
 * Called by manual refresh button or auto-refresh interval.
 */
const refreshDashboard = async () => {
  showLoading();
  try {
    await fetchDashboardData();
    hideLoading();
  } catch (error) {
    hideLoading();
    showError('Failed to refresh dashboard data.');
  }
};

// ============================================================================
// API COMMUNICATION
// ============================================================================

/**
 * Fetches dashboard data from the backend /analyze endpoint.
 * Handles error scenarios and updates the cached data.
 * 
 * @throws {Error} If API request fails or returns invalid data
 */
const fetchDashboardData = async () => {
  try {
    showLoading();
    
    const response = await fetch('/analyze', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      }
    });
    
    if (!response.ok) {
      throw new Error(`API returned status ${response.status}`);
    }
    
    const data = await response.json();
    
    // Validate response structure
    if (data.status !== 'success') {
      throw new Error('API returned unsuccessful status');
    }
    
    // Cache the data
    cachedDashboardData = data;
    lastUpdateTime = new Date();
    
    // Render all dashboard sections
    renderDashboard(data);
    updateLastUpdatedTime();
    
    hideLoading();
  } catch (error) {
    hideLoading();
    console.error('API fetch error:', error);
    showError(`Failed to fetch dashboard data: ${error.message}`);
  }
};

/**
 * Renders all dashboard components with fetched data.
 * 
 * @param {Object} data - The API response object
 */
const renderDashboard = (data) => {
  populateMetadata(data.metadata);
  populateKPIs(data.ml_detection);
  populateDataset(data.dataset, data.ml_detection);
  populateThreatSummary(data.signature_detection);
  populateConfusionMatrix(data.ml_detection.confusion_matrix);
  populateClassificationTable(data.ml_detection.classification_report);
  renderAttackChart(data.signature_detection.attack_distribution);
  renderFeatureImportanceChart(data.ml_detection.top_features);
  renderPerformanceChart(data.performance);
  generateInsights(data);
  updateApiViewer(data);
};

// ============================================================================
// KEY PERFORMANCE INDICATORS (KPIs)
// ============================================================================

/**
 * Populates KPI cards with key metrics.
 * Includes animated counter effects.
 * 
 * @param {Object} mlDetection - ML detection metrics from API
 */
const populateKPIs = (mlDetection) => {
  // Accuracy KPI
  const accuracyEl = document.getElementById('accuracy');
  if (accuracyEl) {
    const accuracy = (mlDetection.accuracy * 100).toFixed(2);
    accuracyEl.textContent = `${accuracy}%`;
    animateCounter(accuracyEl, accuracy);
  }
  
  // Risk Level KPI
  const riskLevelEl = document.getElementById('riskLevel');
  if (riskLevelEl) {
    const badge = document.createElement('span');
    badge.className = 'risk-badge';
    badge.textContent = 'MEDIUM';
    applyRiskBadgeColor(badge, 'MEDIUM');
    riskLevelEl.innerHTML = '';
    riskLevelEl.appendChild(badge);
  }
  
  // Attack Count KPI
  const attackCountEl = document.getElementById('attackCount');
  if (attackCountEl) {
    attackCountEl.textContent = cachedDashboardData.signature_detection.attacks_detected;
    animateCounter(attackCountEl, cachedDashboardData.signature_detection.attacks_detected);
  }
  
  // Execution Time KPI
  const executionTimeEl = document.getElementById('executionTime');
  if (executionTimeEl) {
    const time = cachedDashboardData.performance.total_execution_ms.toFixed(2);
    executionTimeEl.textContent = formatMilliseconds(time);
  }
};

// ============================================================================
// DATASET INFORMATION
// ============================================================================

/**
 * Populates dataset statistics section.
 * 
 * @param {Object} dataset - Dataset metadata
 * @param {Object} mlDetection - ML metrics including train/test split
 */
const populateDataset = (dataset, mlDetection) => {
  const elements = {
    datasetName: dataset.name,
    samples: dataset.samples,
    features: dataset.features,
    training: mlDetection.training_samples,
    testing: mlDetection.testing_samples
  };
  
  Object.entries(elements).forEach(([id, value]) => {
    const el = document.getElementById(id);
    if (el) {
      el.textContent = value;
    }
  });
};

// ============================================================================
// THREAT SUMMARY
// ============================================================================

/**
 * Populates threat summary statistics.
 * 
 * @param {Object} signatureDetection - Signature-based detection results
 */
const populateThreatSummary = (signatureDetection) => {
  const elements = {
    summaryRisk: signatureDetection.risk_level,
    attackPercent: formatPercentage(signatureDetection.attack_percentage),
    topAttack: signatureDetection.most_frequent_attack,
    rulesTriggered: signatureDetection.rules_triggered
  };
  
  Object.entries(elements).forEach(([id, value]) => {
    const el = document.getElementById(id);
    if (el) {
      if (id === 'summaryRisk') {
        const badge = document.createElement('span');
        badge.className = 'risk-badge';
        badge.textContent = value;
        applyRiskBadgeColor(badge, value);
        el.innerHTML = '';
        el.appendChild(badge);
      } else {
        el.textContent = value;
      }
    }
  });
};

// ============================================================================
// METADATA
// ============================================================================

/**
 * Populates metadata information (framework, API version, generated timestamp).
 * 
 * @param {Object} metadata - API metadata
 */
const populateMetadata = (metadata) => {
  // You can display this in a modal or footer
  console.log('📊 Dashboard Metadata:', metadata);
};

// ============================================================================
// CONFUSION MATRIX
// ============================================================================

/**
 * Populates confusion matrix values.
 * Essential for understanding model performance.
 * 
 * @param {Object} confusionMatrix - Confusion matrix with TP, TN, FP, FN
 */
const populateConfusionMatrix = (confusionMatrix) => {
  const { true_positive: tp, true_negative: tn, false_positive: fp, false_negative: fn } = confusionMatrix;
  
  const elements = {
    tp,
    tn,
    fp,
    fn
  };
  
  Object.entries(elements).forEach(([id, value]) => {
    const el = document.getElementById(id);
    if (el) {
      el.textContent = value;
      animateCounter(el, value);
    }
  });
};

// ============================================================================
// CLASSIFICATION TABLE
// ============================================================================

/**
 * Populates classification report table with per-class metrics.
 * 
 * @param {Object} classificationReport - Classification metrics per class
 */
const populateClassificationTable = (classificationReport) => {
  const tableEl = document.getElementById('classificationTable');
  if (!tableEl) return;
  
  // Clear existing rows (keep header)
  const tbody = tableEl.querySelector('tbody');
  if (tbody) {
    tbody.innerHTML = '';
  }
  
  // Populate with classification data
  Object.entries(classificationReport).forEach(([classLabel, metrics]) => {
    const row = document.createElement('tr');
    
    const classNameMap = {
      '0': 'Normal Traffic',
      '1': 'Attack Traffic'
    };
    
    row.innerHTML = `
      <td><span class="badge bg-info">${classNameMap[classLabel] || `Class ${classLabel}`}</span></td>
      <td>${formatPercentage(metrics.precision * 100)}</td>
      <td>${formatPercentage(metrics.recall * 100)}</td>
      <td>${formatPercentage(metrics['f1-score'] * 100)}</td>
      <td><span class="badge bg-primary">${metrics.support}</span></td>
    `;
    
    tbody.appendChild(row);
  });
};

// ============================================================================
// CHART RENDERING
// ============================================================================

/**
 * Destroys existing Chart.js instances to prevent memory leaks.
 * Must be called before recreating charts.
 */
const destroyExistingCharts = () => {
  Object.values(chartInstances).forEach(chart => {
    if (chart instanceof Chart) {
      chart.destroy();
    }
  });
};

/**
 * Renders attack distribution pie chart.
 * Shows ratio of different attack types detected.
 * 
 * @param {Object} attackDistribution - Attack counts by type
 */
const renderAttackChart = (attackDistribution) => {
  const ctx = document.getElementById('attackChart');
  if (!ctx) return;
  
  // Destroy existing chart
  if (chartInstances.attackChart) {
    chartInstances.attackChart.destroy();
  }
  
  const labels = Object.keys(attackDistribution);
  const data = Object.values(attackDistribution);
  
  // Generate distinct colors for attack types
  const backgroundColors = [
    CHART_CONFIG.colors.red,
    CHART_CONFIG.colors.orange,
    CHART_CONFIG.colors.blue,
    CHART_CONFIG.colors.purple
  ];
  
  chartInstances.attackChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{
        data: data,
        backgroundColor: backgroundColors.slice(0, labels.length),
        borderColor: '#1f2937',
        borderWidth: 2,
        hoverOffset: 8
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            color: CHART_CONFIG.theme.textColor,
            font: {
              size: 12,
              weight: '500'
            },
            padding: 15
          }
        },
        tooltip: {
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          titleColor: CHART_CONFIG.theme.textColor,
          bodyColor: CHART_CONFIG.theme.textColor,
          padding: 12,
          displayColors: true,
          callbacks: {
            label: (context) => {
              const total = context.dataset.data.reduce((a, b) => a + b, 0);
              const percentage = ((context.raw / total) * 100).toFixed(1);
              return `${context.label}: ${context.raw} (${percentage}%)`;
            }
          }
        }
      }
    }
  });
};

/**
 * Renders feature importance horizontal bar chart.
 * Shows which features have the highest predictive value.
 * 
 * @param {Array} topFeatures - Top features with importance scores
 */
const renderFeatureImportanceChart = (topFeatures) => {
  const ctx = document.getElementById('featureChart');
  if (!ctx) return;
  
  // Destroy existing chart
  if (chartInstances.featureChart) {
    chartInstances.featureChart.destroy();
  }
  
  // Sort features by importance (descending)
  const sortedFeatures = [...topFeatures].sort((a, b) => b.importance - a.importance);
  
  const labels = sortedFeatures.map(f => f.feature);
  const data = sortedFeatures.map(f => (f.importance * 100).toFixed(2));
  
  chartInstances.featureChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Feature Importance (%)',
        data: data,
        backgroundColor: CHART_CONFIG.colors.blue,
        borderColor: CHART_CONFIG.colors.blue,
        borderWidth: 1,
        borderRadius: 4,
        hoverBackgroundColor: CHART_CONFIG.colors.purple
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          display: true,
          labels: {
            color: CHART_CONFIG.theme.textColor,
            font: {
              size: 12,
              weight: '500'
            }
          }
        },
        tooltip: {
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          titleColor: CHART_CONFIG.theme.textColor,
          bodyColor: CHART_CONFIG.theme.textColor,
          padding: 10,
          callbacks: {
            label: (context) => `${context.raw}% importance`
          }
        }
      },
      scales: {
        x: {
          beginAtZero: true,
          max: 100,
          ticks: {
            color: CHART_CONFIG.theme.textColor,
            callback: (value) => `${value}%`
          },
          grid: {
            color: CHART_CONFIG.theme.gridColor
          }
        },
        y: {
          ticks: {
            color: CHART_CONFIG.theme.textColor,
            font: {
              size: 11
            }
          },
          grid: {
            display: false
          }
        }
      }
    }
  });
};

/**
 * Renders performance metrics vertical bar chart.
 * Shows processing time breakdown by stage.
 * 
 * @param {Object} performance - Performance metrics in milliseconds
 */
const renderPerformanceChart = (performance) => {
  const ctx = document.getElementById('performanceChart');
  if (!ctx) return;
  
  // Destroy existing chart
  if (chartInstances.performanceChart) {
    chartInstances.performanceChart.destroy();
  }
  
  // Extract meaningful performance metrics
  const stages = [
    { label: 'Dataset Loading', value: performance.dataset_loading_ms },
    { label: 'Data Cleaning', value: performance.cleaning_ms },
    { label: 'Feature Encoding', value: performance.encoding_ms },
    { label: 'Signature Detection', value: performance.signature_detection_ms },
    { label: 'Model Training', value: performance.model_training_ms },
    { label: 'Model Prediction', value: performance.model_prediction_ms }
  ];
  
  const labels = stages.map(s => s.label);
  const data = stages.map(s => parseFloat(s.value.toFixed(1)));
  
  chartInstances.performanceChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Processing Time (ms)',
        data: data,
        backgroundColor: CHART_CONFIG.colors.green,
        borderColor: CHART_CONFIG.colors.green,
        borderWidth: 1,
        borderRadius: 4,
        hoverBackgroundColor: CHART_CONFIG.colors.cyan
      }]
    },
    options: {
      indexAxis: 'x',
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: {
          display: true,
          labels: {
            color: CHART_CONFIG.theme.textColor,
            font: {
              size: 12,
              weight: '500'
            }
          }
        },
        tooltip: {
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          titleColor: CHART_CONFIG.theme.textColor,
          bodyColor: CHART_CONFIG.theme.textColor,
          padding: 10,
          callbacks: {
            label: (context) => `${context.raw}ms`
          }
        }
      },
      scales: {
        x: {
          ticks: {
            color: CHART_CONFIG.theme.textColor,
            font: {
              size: 11
            }
          },
          grid: {
            display: false
          }
        },
        y: {
          beginAtZero: true,
          ticks: {
            color: CHART_CONFIG.theme.textColor,
            callback: (value) => `${value}ms`
          },
          grid: {
            color: CHART_CONFIG.theme.gridColor
          }
        }
      }
    }
  });
};

// ============================================================================
// AI INSIGHTS GENERATION
// ============================================================================

/**
 * Generates professional insights from dashboard data.
 * Provides actionable, intelligent observations about the security posture.
 * 
 * @param {Object} data - Complete API response
 */
const generateInsights = (data) => {
  const insights = [];
  
  const ml = data.ml_detection;
  const sig = data.signature_detection;
  const perf = data.performance;
  
  // Insight 1: Model Accuracy
  const accuracy = (ml.accuracy * 100).toFixed(2);
  insights.push(`✓ Model Accuracy is ${accuracy}%. Excellent performance on test dataset.`);
  
  // Insight 2: Most Frequent Attack
  insights.push(`✓ ${sig.most_frequent_attack} attacks dominate the dataset with ${sig.attack_distribution[sig.most_frequent_attack]} detected incidents.`);
  
  // Insight 3: Performance Bottleneck
  const perfEntries = Object.entries(perf)
    .filter(([key]) => key.includes('_ms'))
    .sort(([, a], [, b]) => b - a);
  
  if (perfEntries.length > 0) {
    const [slowestStage, slowestTime] = perfEntries[0];
    const stageName = slowestStage.replace('_ms', '').replace(/_/g, ' ');
    insights.push(`✓ ${stageName} consumes the highest processing time (${slowestTime.toFixed(1)}ms).`);
  }
  
  // Insight 4: Top Feature
  if (ml.top_features && ml.top_features.length > 0) {
    const topFeature = ml.top_features[0];
    const importance = (topFeature.importance * 100).toFixed(1);
    insights.push(`✓ Random Forest relies primarily on '${topFeature.feature}' feature (${importance}% importance).`);
  }
  
  // Insight 5: Overall Threat Level
  insights.push(`✓ Overall threat level is ${sig.risk_level}. Monitor rules triggered: ${sig.rules_triggered}.`);
  
  // Render insights
  const insightListEl = document.getElementById('insightList');
  if (insightListEl) {
    insightListEl.innerHTML = insights
      .map(insight => `<li class="list-group-item bg-dark border-secondary text-light">${insight}</li>`)
      .join('');
  }
};

// ============================================================================
// API RESPONSE VIEWER
// ============================================================================

/**
 * Updates raw API response viewer for debugging/transparency.
 * 
 * @param {Object} data - API response data
 */
const updateApiViewer = (data) => {
  const apiResponseEl = document.getElementById('apiResponse');
  if (apiResponseEl) {
    apiResponseEl.textContent = JSON.stringify(data, null, 2);
  }
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Shows loading spinner/overlay.
 * Call before making API requests.
 */
const showLoading = () => {
  const spinner = document.getElementById('loadingSpinner');
  if (spinner) {
    spinner.style.display = 'flex';
  }
};

/**
 * Hides loading spinner/overlay.
 * Call after API request completes.
 */
const hideLoading = () => {
  const spinner = document.getElementById('loadingSpinner');
  if (spinner) {
    spinner.style.display = 'none';
  }
};

/**
 * Shows error alert to user.
 * 
 * @param {string} message - Error message to display
 */
const showError = (message) => {
  const alertContainer = document.getElementById('alertContainer');
  if (!alertContainer) return;
  
  const alertHtml = `
    <div class="alert alert-danger alert-dismissible fade show" role="alert">
      <strong>⚠️ Error:</strong> ${message}
      <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    </div>
  `;
  
  alertContainer.insertAdjacentHTML('beforeend', alertHtml);
  
  // Auto-dismiss after 6 seconds
  setTimeout(() => {
    const alert = alertContainer.querySelector('.alert-danger');
    if (alert) {
      const bsAlert = new bootstrap.Alert(alert);
      bsAlert.close();
    }
  }, 6000);
};

/**
 * Formats decimal percentage values.
 * 
 * @param {number} value - Percentage value
 * @returns {string} Formatted percentage with 2 decimal places
 */
const formatPercentage = (value) => {
  return `${parseFloat(value).toFixed(2)}%`;
};

/**
 * Formats milliseconds into human-readable format.
 * 
 * @param {number} ms - Milliseconds
 * @returns {string} Formatted time string
 */
const formatMilliseconds = (ms) => {
  if (ms < 1000) {
    return `${parseFloat(ms).toFixed(1)}ms`;
  }
  const seconds = (ms / 1000).toFixed(2);
  return `${seconds}s`;
};

/**
 * Applies risk level badge coloring.
 * Color indicates severity: RED=CRITICAL, ORANGE=HIGH, YELLOW=MEDIUM, GREEN=LOW
 * 
 * @param {HTMLElement} element - Element to apply color to
 * @param {string} riskLevel - Risk level (CRITICAL, HIGH, MEDIUM, LOW)
 */
const applyRiskBadgeColor = (element, riskLevel) => {
  const colorMap = {
    'CRITICAL': '#dc2626',
    'HIGH': '#f59e0b',
    'MEDIUM': '#38bdf8',
    'LOW': '#22c55e'
  };
  const textColorMap = {
    'CRITICAL': '#ffffff',
    'HIGH': '#0f172a',
    'MEDIUM': '#020617',
    'LOW': '#020617'
  };

  const backgroundColor = colorMap[riskLevel] || '#64748b';
  const textColor = textColorMap[riskLevel] || '#ffffff';

  element.style.backgroundColor = backgroundColor;
  element.style.color = textColor;
  element.style.border = '1px solid rgba(255,255,255,0.12)';
  element.style.boxShadow = '0 10px 25px rgba(0,0,0,0.18)';
};

/**
 * Animates counter from 0 to target value.
 * Creates engaging visual feedback for numeric KPIs.
 * 
 * @param {HTMLElement} element - Element containing the number
 * @param {number} targetValue - Target value to animate to
 * @param {number} duration - Animation duration in ms (default: 1500)
 */
const animateCounter = (element, targetValue, duration = 1500) => {
  const startValue = 0;
  const startTime = Date.now();
  
  const animateStep = () => {
    const elapsed = Date.now() - startTime;
    const progress = Math.min(elapsed / duration, 1);
    
    // Easing function for smooth animation
    const easeOut = 1 - Math.pow(1 - progress, 3);
    
    const currentValue = startValue + (targetValue - startValue) * easeOut;
    
    // Format the display value
    if (typeof targetValue === 'string') {
      element.textContent = currentValue.toFixed(2);
    } else if (Number.isInteger(targetValue)) {
      element.textContent = Math.round(currentValue);
    } else {
      element.textContent = currentValue.toFixed(2);
    }
    
    if (progress < 1) {
      requestAnimationFrame(animateStep);
    }
  };
  
  requestAnimationFrame(animateStep);
};

/**
 * Updates the "Last Updated" timestamp display.
 * Provides transparency about data freshness.
 */
const updateLastUpdatedTime = () => {
  const lastUpdatedEl = document.getElementById('lastUpdated');
  if (lastUpdatedEl && lastUpdateTime) {
    const timeString = lastUpdateTime.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
    lastUpdatedEl.textContent = `Last updated: ${timeString}`;
  }
};

// ============================================================================
// EVENT LISTENERS & AUTO-REFRESH
// ============================================================================

/**
 * Setup auto-refresh interval.
 * Refreshes dashboard data every 30 seconds.
 */
const setupAutoRefresh = () => {
  setInterval(() => {
    fetchDashboardData();
  }, 30000); // 30 seconds
};

// ============================================================================
// BOOTSTRAP INITIALIZATION
// ============================================================================

/**
 * Initialize dashboard when DOM is ready.
 * Waits for all DOM elements to be loaded before setup.
 */
document.addEventListener('DOMContentLoaded', () => {
  initializeDashboard();
  setupAutoRefresh();
});

// ============================================================================
// ERROR BOUNDARY
// ============================================================================

/**
 * Global error handler to prevent unhandled promise rejections.
 */
window.addEventListener('unhandledrejection', (event) => {
  console.error('Unhandled promise rejection:', event.reason);
  showError('An unexpected error occurred. Please refresh the page.');
});

/**
 * Global error handler for runtime errors.
 */
window.addEventListener('error', (event) => {
  console.error('Global error:', event.error);
  showError(`An error occurred: ${event.error?.message || 'Unknown error'}`);
});
