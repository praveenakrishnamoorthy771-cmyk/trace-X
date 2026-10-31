/**
 * TRACE-X | Cybersecurity Investigation Engine
 * Generic & Dynamic Application Logic
 * Supports 6 AVAILABLE categories, evidence card shuffling, neutral telemetry parsing, and 40/30/30 robust scoring.
 */

// Application State
const state = {
  currentScreen: 'landing', // 'landing', 'categories', 'scenarios', 'investigation'
  currentCategory: null,
  currentScenario: null,
  currentStage: 1, // 1: Brief, 2: Evidence, 3: Timeline, 4: MITRE, 5: Causal, 6: Report
  
  shuffledEvents: [],      // Randomized event order for Evidence Board
  selectedEvidenceIds: [],  // Array of event IDs selected by user
  timelineOrder: [],        // Chronologically arranged event IDs by user
  mitreMapping: {},         // EventId -> MitreId mapping
  causalLinks: [],          // Array of objects [{cause: 'EV-01', effect: 'EV-03'}]
  
  scores: {
    timelineSelection: 0,   // Max 40
    mitre: 0,               // Max 30
    causal: 0,              // Max 30
    total: 0                // Max 100
  }
};

// DOM Initialization
document.addEventListener('DOMContentLoaded', () => {
  initApp();
});

function initApp() {
  bindEvents();
  renderCategories();
  showScreen('landing');
}

/* ==========================================================================
   NAVIGATION & SCREEN MANAGEMENT
   ========================================================================== */

function showScreen(screenId) {
  state.currentScreen = screenId;
  document.querySelectorAll('.screen').forEach(screen => {
    screen.classList.remove('active');
  });

  const targetScreen = document.getElementById(`screen-${screenId}`);
  if (targetScreen) {
    targetScreen.classList.add('active');
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }
}

function bindEvents() {
  // Navigation Bar Links
  document.getElementById('logo-btn').addEventListener('click', () => showScreen('landing'));
  document.getElementById('nav-categories-btn').addEventListener('click', () => showScreen('categories'));
  document.getElementById('start-investigation-btn').addEventListener('click', () => showScreen('categories'));
  
  // Breadcrumbs
  document.getElementById('crumb-home')?.addEventListener('click', () => showScreen('landing'));
  document.getElementById('crumb-home-2')?.addEventListener('click', () => showScreen('landing'));
  document.getElementById('crumb-categories')?.addEventListener('click', () => showScreen('categories'));
  
  document.getElementById('back-to-categories-btn').addEventListener('click', () => showScreen('categories'));
  document.getElementById('exit-investigation-btn').addEventListener('click', () => showScreen('scenarios'));
  
  // Stepper Stage Navigation
  document.querySelectorAll('.step-item').forEach(item => {
    item.addEventListener('click', () => {
      const stageNum = parseInt(item.getAttribute('data-stage'), 10);
      if (stageNum <= getMaxAllowedStage()) {
        goToStage(stageNum);
      } else {
        showToast('Complete current stage requirements before advancing', 'warn');
      }
    });
  });

  // Stage Next / Back Buttons
  document.getElementById('start-evidence-stage-btn').addEventListener('click', () => goToStage(2));
  document.getElementById('back-to-brief-btn').addEventListener('click', () => goToStage(1));
  document.getElementById('goto-timeline-btn').addEventListener('click', validateAndProceedToTimeline);
  document.getElementById('back-to-evidence-btn').addEventListener('click', () => goToStage(2));
  document.getElementById('goto-mitre-btn').addEventListener('click', () => goToStage(4));
  document.getElementById('back-to-timeline-btn').addEventListener('click', () => goToStage(3));
  document.getElementById('goto-causal-btn').addEventListener('click', () => goToStage(5));
  document.getElementById('back-to-mitre-btn').addEventListener('click', () => goToStage(4));
  document.getElementById('add-causal-link-btn').addEventListener('click', handleAddCausalLink);
  document.getElementById('submit-investigation-btn').addEventListener('click', handleCalculateAndShowReport);
  
  // Report Buttons
  document.getElementById('retry-investigation-btn').addEventListener('click', resetAndRestartInvestigation);
  document.getElementById('report-to-scenarios-btn').addEventListener('click', () => showScreen('scenarios'));
  document.getElementById('report-to-categories-btn').addEventListener('click', () => showScreen('categories'));
}

function getMaxAllowedStage() {
  if (state.selectedEvidenceIds.length === 8) return 6;
  return 2;
}

/* ==========================================================================
   CATEGORY SELECTION SYSTEM
   ========================================================================== */

function renderCategories() {
  const container = document.getElementById('categories-container');
  if (!container) return;

  container.innerHTML = '';

  TRACE_DATA.categories.forEach(cat => {
    const isAvailable = cat.status === 'Available';
    
    const card = document.createElement('div');
    card.className = `glass-panel category-card available`;
    
    card.innerHTML = `
      <div>
        <div class="category-card-top">
          <div class="category-icon-box">
            <i class="fa-solid ${cat.icon}"></i>
          </div>
          <span class="badge badge-available">
            <i class="fa-solid fa-circle-check"></i> Available
          </span>
        </div>
        
        <h3 class="category-title">${cat.name}</h3>
        <p class="category-desc">${cat.description}</p>
      </div>

      <div class="category-meta">
        <span class="scenario-count">
          <i class="fa-solid fa-folder-open"></i> ${cat.availableScenariosCount} Scenario${cat.availableScenariosCount !== 1 ? 's' : ''}
        </span>
        <button class="btn btn-primary btn-sm">
          Start Investigation <i class="fa-solid fa-arrow-right"></i>
        </button>
      </div>
    `;

    card.addEventListener('click', () => {
      selectCategory(cat.id);
    });

    container.appendChild(card);
  });
}

function selectCategory(catId) {
  const category = TRACE_DATA.categories.find(c => c.id === catId);
  if (!category) return;

  state.currentCategory = category;
  
  document.getElementById('crumb-current-cat').textContent = category.name;
  document.getElementById('scenario-cat-title').textContent = category.name;
  document.getElementById('scenario-cat-desc').textContent = category.description;

  renderScenarios(category);
  showScreen('scenarios');
}

/* ==========================================================================
   SCENARIO SELECTION SYSTEM
   ========================================================================== */

function renderScenarios(category) {
  const container = document.getElementById('scenarios-container');
  if (!container) return;

  container.innerHTML = '';

  if (!category.scenarios || category.scenarios.length === 0) {
    container.innerHTML = `
      <div class="glass-panel" style="padding: 40px; text-align: center; grid-column: 1 / -1;">
        <i class="fa-solid fa-folder-open text-muted" style="font-size: 2.5rem; margin-bottom: 16px;"></i>
        <h3>No Scenarios Available</h3>
        <p class="text-sub">There are currently no active scenarios under this category.</p>
      </div>
    `;
    return;
  }

  category.scenarios.forEach(scenarioId => {
    const scenario = TRACE_DATA.scenarios[scenarioId];
    if (!scenario) return;

    const card = document.createElement('div');
    card.className = 'glass-panel scenario-card';

    card.innerHTML = `
      <div class="scenario-header">
        <span class="badge badge-difficulty">
          <i class="fa-solid fa-gauge-high"></i> ${scenario.difficulty}
        </span>
        <span class="badge badge-available">
          <i class="fa-solid fa-circle-check"></i> ${scenario.status}
        </span>
      </div>

      <h3 class="scenario-title">${scenario.name}</h3>
      <p class="category-desc">${scenario.description}</p>

      <div class="scenario-details">
        <div class="scenario-detail-item">
          <i class="fa-solid fa-stopwatch text-cyan"></i>
          <span>${scenario.estimatedTime}</span>
        </div>
        <div class="scenario-detail-item">
          <i class="fa-solid fa-list-ol text-green"></i>
          <span>${scenario.events ? scenario.events.length : 12} Evidence Logs</span>
        </div>
      </div>

      <button class="btn btn-primary" style="margin-top: auto;">
        Start Investigation <i class="fa-solid fa-play"></i>
      </button>
    `;

    card.querySelector('button').addEventListener('click', (e) => {
      e.stopPropagation();
      startScenario(scenarioId);
    });

    card.addEventListener('click', () => {
      startScenario(scenarioId);
    });

    container.appendChild(card);
  });
}

function startScenario(scenarioId) {
  const scenario = TRACE_DATA.scenarios[scenarioId];
  if (!scenario) return;

  state.currentScenario = scenario;
  resetInvestigationState();

  // Create randomized shuffle of events for evidence board
  state.shuffledEvents = shuffleArray([...scenario.events]);

  // Load Brief Data
  document.getElementById('inv-case-id').textContent = scenario.brief.caseId;
  document.getElementById('inv-scenario-name').textContent = scenario.name;
  document.getElementById('brief-severity').textContent = scenario.brief.severity;
  document.getElementById('brief-title').textContent = scenario.brief.title;
  document.getElementById('brief-summary').textContent = scenario.brief.summary;
  document.getElementById('brief-target').textContent = scenario.brief.target;
  document.getElementById('brief-date').textContent = scenario.brief.incidentDate;
  document.getElementById('brief-time').textContent = scenario.estimatedTime;
  document.getElementById('brief-objective').textContent = scenario.brief.objective;

  renderEvidenceCards();
  showScreen('investigation');
  goToStage(1);
}

function shuffleArray(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

function resetInvestigationState() {
  state.selectedEvidenceIds = [];
  state.timelineOrder = [];
  state.mitreMapping = {};
  state.causalLinks = [];
  state.scores = { timelineSelection: 0, mitre: 0, causal: 0, total: 0 };
}

function resetAndRestartInvestigation() {
  if (state.currentScenario) {
    startScenario(state.currentScenario.id);
  }
}

/* ==========================================================================
   INVESTIGATION ENGINE STAGES
   ========================================================================== */

function goToStage(stageNum) {
  state.currentStage = stageNum;

  document.querySelectorAll('.step-item').forEach(item => {
    const s = parseInt(item.getAttribute('data-stage'), 10);
    item.classList.remove('active', 'completed');
    if (s === stageNum) {
      item.classList.add('active');
    } else if (s < stageNum) {
      item.classList.add('completed');
    }
  });

  document.querySelectorAll('.stage-panel').forEach(panel => {
    panel.classList.remove('active');
  });

  const stages = ['brief', 'evidence', 'timeline', 'mitre', 'causal', 'report'];
  const targetPanel = document.getElementById(`stage-${stages[stageNum - 1]}`);
  if (targetPanel) {
    targetPanel.classList.add('active');
  }

  if (stageNum === 3) renderTimelineItems();
  if (stageNum === 4) renderMitreItems();
  if (stageNum === 5) renderCausalStage();
}

/* STAGE 2: EVIDENCE BOARD */
function renderEvidenceCards() {
  const container = document.getElementById('evidence-cards-container');
  if (!container || !state.currentScenario) return;

  container.innerHTML = '';
  updateEvidenceCounter();

  state.shuffledEvents.forEach(ev => {
    const isSelected = state.selectedEvidenceIds.includes(ev.id);
    
    const card = document.createElement('div');
    card.className = `glass-panel evidence-card ${isSelected ? 'selected' : ''}`;
    card.setAttribute('data-id', ev.id);

    card.innerHTML = `
      <div class="evidence-check">
        <i class="fa-solid fa-check"></i>
      </div>
      <div class="evidence-header">
        <span class="evidence-id">${ev.id}</span>
        <span class="evidence-time"><i class="fa-solid fa-clock"></i> ${ev.timestamp}</span>
      </div>
      <h4 class="evidence-title">${ev.title}</h4>
      <div class="evidence-source">
        <i class="fa-solid fa-desktop"></i> ${ev.host || 'ENDPOINT'} &nbsp;|&nbsp; 
        <i class="fa-solid fa-user"></i> ${ev.user || 'USER'} &nbsp;|&nbsp; 
        <i class="fa-solid fa-server"></i> ${ev.source}
      </div>
      <p class="evidence-details">${ev.details}</p>
    `;

    card.addEventListener('click', () => toggleEvidenceSelection(ev.id, card));
    container.appendChild(card);
  });
}

function toggleEvidenceSelection(evId, cardElement) {
  const index = state.selectedEvidenceIds.indexOf(evId);
  
  if (index > -1) {
    state.selectedEvidenceIds.splice(index, 1);
    cardElement.classList.remove('selected');
  } else {
    if (state.selectedEvidenceIds.length >= 8) {
      showToast('Maximum 8 evidence events allowed', 'warn');
      return;
    }
    state.selectedEvidenceIds.push(evId);
    cardElement.classList.add('selected');
  }

  updateEvidenceCounter();
}

function updateEvidenceCounter() {
  const el = document.getElementById('evidence-selected-count');
  if (el) {
    el.textContent = state.selectedEvidenceIds.length;
  }
}

function validateAndProceedToTimeline() {
  if (state.selectedEvidenceIds.length !== 8) {
    showToast(`Select exactly 8 evidence events (Currently: ${state.selectedEvidenceIds.length})`, 'warn');
    return;
  }

  if (state.timelineOrder.length !== 8) {
    state.timelineOrder = [...state.selectedEvidenceIds];
  }

  goToStage(3);
}

/* STAGE 3: TIMELINE RECONSTRUCTION */
function renderTimelineItems() {
  const container = document.getElementById('timeline-items-container');
  if (!container || !state.currentScenario) return;

  container.innerHTML = '';

  state.timelineOrder.forEach((evId, index) => {
    const ev = state.currentScenario.events.find(e => e.id === evId);
    if (!ev) return;

    const item = document.createElement('div');
    item.className = 'glass-panel timeline-item';

    item.innerHTML = `
      <div class="timeline-rank">${index + 1}</div>
      <div class="timeline-content">
        <div style="display: flex; gap: 10px; align-items: center; margin-bottom: 4px;">
          <span class="evidence-id">${ev.id}</span>
          <span class="evidence-time">${ev.timestamp}</span>
        </div>
        <h4 style="font-size: 0.98rem;">${ev.title}</h4>
      </div>
      <div class="timeline-actions">
        <button class="btn-move btn-up" ${index === 0 ? 'disabled' : ''} title="Move Up">
          <i class="fa-solid fa-chevron-up"></i>
        </button>
        <button class="btn-move btn-down" ${index === state.timelineOrder.length - 1 ? 'disabled' : ''} title="Move Down">
          <i class="fa-solid fa-chevron-down"></i>
        </button>
      </div>
    `;

    item.querySelector('.btn-up').addEventListener('click', () => moveTimelineItem(index, -1));
    item.querySelector('.btn-down').addEventListener('click', () => moveTimelineItem(index, 1));

    container.appendChild(item);
  });
}

function moveTimelineItem(index, delta) {
  const newIndex = index + delta;
  if (newIndex < 0 || newIndex >= state.timelineOrder.length) return;

  const temp = state.timelineOrder[index];
  state.timelineOrder[index] = state.timelineOrder[newIndex];
  state.timelineOrder[newIndex] = temp;

  renderTimelineItems();
}

/* STAGE 4: MITRE ATT&CK ATTRIBUTION */
function renderMitreItems() {
  const container = document.getElementById('mitre-items-container');
  if (!container || !state.currentScenario) return;

  container.innerHTML = '';

  state.timelineOrder.forEach(evId => {
    const ev = state.currentScenario.events.find(e => e.id === evId);
    if (!ev) return;

    const currentMitre = state.mitreMapping[evId] || '';

    const card = document.createElement('div');
    card.className = 'glass-panel mitre-card';

    let optionsHtml = `<option value="">-- Select MITRE ATT&CK Technique --</option>`;
    state.currentScenario.mitreOptions.forEach(opt => {
      optionsHtml += `<option value="${opt.id}" ${opt.id === currentMitre ? 'selected' : ''}>${opt.name}</option>`;
    });

    card.innerHTML = `
      <div>
        <div style="display: flex; gap: 10px; align-items: center; margin-bottom: 6px;">
          <span class="evidence-id">${ev.id}</span>
          <h4 style="font-size: 0.96rem;">${ev.title}</h4>
        </div>
        <p class="text-sub" style="font-size: 0.85rem;">${ev.details}</p>
      </div>
      <div>
        <select class="mitre-select" data-id="${ev.id}">
          ${optionsHtml}
        </select>
      </div>
    `;

    card.querySelector('select').addEventListener('change', (e) => {
      state.mitreMapping[evId] = e.target.value;
    });

    container.appendChild(card);
  });
}

/* STAGE 5: CAUSAL RELATIONSHIP MAPPING */
function renderCausalStage() {
  const causeSelect = document.getElementById('causal-cause-select');
  const effectSelect = document.getElementById('causal-effect-select');
  
  if (!causeSelect || !effectSelect || !state.currentScenario) return;

  let optionsHtml = `<option value="">-- Select Event --</option>`;
  state.timelineOrder.forEach(evId => {
    const ev = state.currentScenario.events.find(e => e.id === evId);
    if (ev) {
      optionsHtml += `<option value="${ev.id}">${ev.id}: ${ev.title}</option>`;
    }
  });

  causeSelect.innerHTML = optionsHtml;
  effectSelect.innerHTML = optionsHtml;

  renderCausalLinksList();
}

function handleAddCausalLink() {
  const causeSelect = document.getElementById('causal-cause-select');
  const effectSelect = document.getElementById('causal-effect-select');

  const cause = causeSelect.value;
  const effect = effectSelect.value;

  if (!cause || !effect) {
    showToast('Select both a Cause event and an Effect event', 'warn');
    return;
  }

  if (cause === effect) {
    showToast('Cause and Effect cannot be the same event', 'warn');
    return;
  }

  const exists = state.causalLinks.some(link => link.cause === cause && link.effect === effect);
  if (exists) {
    showToast('Causal link already exists', 'warn');
    return;
  }

  state.causalLinks.push({ cause, effect });
  showToast(`Connected ${cause} → ${effect}`, 'success');

  causeSelect.value = '';
  effectSelect.value = '';
  renderCausalLinksList();
}

function renderCausalLinksList() {
  const container = document.getElementById('causal-links-container');
  if (!container || !state.currentScenario) return;

  container.innerHTML = '';

  if (state.causalLinks.length === 0) {
    container.innerHTML = `
      <div class="glass-panel" style="padding: 24px; text-align: center; color: var(--text-muted);">
        No causal links added yet. Use the selector above to link dependent events.
      </div>
    `;
    return;
  }

  state.causalLinks.forEach((link, idx) => {
    const causeEv = state.currentScenario.events.find(e => e.id === link.cause);
    const effectEv = state.currentScenario.events.find(e => e.id === link.effect);

    const card = document.createElement('div');
    card.className = 'glass-panel causal-link-card';

    card.innerHTML = `
      <div class="causal-flow">
        <span class="evidence-id">${link.cause}</span>
        <span class="text-sub" style="font-size: 0.85rem;">(${causeEv ? causeEv.title : ''})</span>
        <i class="fa-solid fa-right-long causal-arrow"></i>
        <span class="evidence-id">${link.effect}</span>
        <span class="text-sub" style="font-size: 0.85rem;">(${effectEv ? effectEv.title : ''})</span>
      </div>
      <button class="btn btn-secondary btn-sm" style="color: var(--red-danger);" title="Remove Link">
        <i class="fa-solid fa-trash"></i>
      </button>
    `;

    card.querySelector('button').addEventListener('click', () => {
      state.causalLinks.splice(idx, 1);
      renderCausalLinksList();
    });

    container.appendChild(card);
  });
}

/* ==========================================================================
   SCORING ENGINE & REPORT GENERATION (40 / 30 / 30 TOTAL = 100)
   ========================================================================== */

function handleCalculateAndShowReport() {
  const answerKey = state.currentScenario.answerKey;
  if (!answerKey) return;

  // 1. Evidence Selection & Timeline Order Score (40 Points Max)
  let selectionPoints = 0;
  answerKey.relevantEventIds.forEach(id => {
    if (state.selectedEvidenceIds.includes(id)) {
      selectionPoints += 2.5;
    }
  });

  state.selectedEvidenceIds.forEach(id => {
    if (!answerKey.relevantEventIds.includes(id)) {
      selectionPoints -= 2.5; // Decoy penalty
    }
  });
  selectionPoints = Math.max(0, selectionPoints);

  let orderPoints = 0;
  state.timelineOrder.forEach((id, index) => {
    const expectedIndex = answerKey.timelineOrder.indexOf(id);
    if (expectedIndex === index) {
      orderPoints += 2.5;
    }
  });

  const timelineSelectionScore = Math.min(40, Math.round(selectionPoints + orderPoints));

  // 2. MITRE ATT&CK Attribution Score (30 Points Max)
  let mitreScore = 0;
  Object.keys(answerKey.mitreMapping).forEach(evId => {
    if (state.mitreMapping[evId] === answerKey.mitreMapping[evId]) {
      mitreScore += 3.75;
    }
  });
  mitreScore = Math.min(30, Math.round(mitreScore));

  // 3. Causal Relationships Score (30 Points Max)
  let correctCausalCount = 0;
  let incorrectCausalCount = 0;

  state.causalLinks.forEach(link => {
    const isCorrect = answerKey.causalPairs.some(p => p.cause === link.cause && p.effect === link.effect);
    if (isCorrect) {
      correctCausalCount++;
    } else {
      incorrectCausalCount++;
    }
  });

  let rawCausalScore = (correctCausalCount * 4.2857) - (incorrectCausalCount * 4.2857);
  const causalScore = Math.max(0, Math.min(30, Math.round(rawCausalScore)));

  const totalScore = timelineSelectionScore + mitreScore + causalScore;

  state.scores = {
    timelineSelection: timelineSelectionScore,
    mitre: mitreScore,
    causal: causalScore,
    total: totalScore
  };

  renderReportUI();
  goToStage(6);
}

function renderReportUI() {
  const scores = state.scores;

  document.getElementById('final-total-score').textContent = scores.total;
  document.getElementById('score-timeline').textContent = `${scores.timelineSelection} / 40`;
  document.getElementById('score-mitre').textContent = `${scores.mitre} / 30`;
  document.getElementById('score-causal').textContent = `${scores.causal} / 30`;

  const ratingTitle = document.getElementById('final-rating-title');
  const ratingDesc = document.getElementById('final-rating-desc');
  const narrativeContainer = document.getElementById('report-narrative');

  if (scores.total === 100) {
    ratingTitle.textContent = "MASTER INCIDENT RESPONDER";
    ratingTitle.className = "text-green";
    ratingDesc.textContent = "Flawless forensic investigation! 100/100 score achieved. All 8 relevant evidence events identified, attack timeline reconstructed, MITRE ATT&CK techniques attributed, and causal chain established.";
  } else if (scores.total >= 75) {
    ratingTitle.textContent = "SENIOR SECURITY ANALYST";
    ratingTitle.className = "text-cyan";
    ratingDesc.textContent = "Strong investigation performance. The majority of telemetry artifacts were correctly isolated and mapped. Review minor discrepancies in the audit log below.";
  } else {
    ratingTitle.textContent = "JUNIOR TRIAGE ANALYST";
    ratingTitle.className = "text-amber";
    ratingDesc.textContent = "Investigation completed. Several critical evidence artifacts or MITRE attributions were missed. Re-examine raw log details and retry.";
  }

  // Final Attack Narrative
  if (narrativeContainer && state.currentScenario && state.currentScenario.answerKey) {
    narrativeContainer.textContent = state.currentScenario.answerKey.narrative;
  }

  // Audit Table Rendering
  const tbody = document.getElementById('audit-table-body');
  if (!tbody || !state.currentScenario) return;

  tbody.innerHTML = '';
  const answerKey = state.currentScenario.answerKey;

  state.currentScenario.events.forEach(ev => {
    const isSelected = state.selectedEvidenceIds.includes(ev.id);
    const isCorrectSelection = ev.isRelevant === isSelected;
    
    const userRank = state.timelineOrder.indexOf(ev.id);
    const correctRank = answerKey.timelineOrder.indexOf(ev.id);
    const isTimelineCorrect = ev.isRelevant ? (userRank === correctRank) : 'N/A';

    const userMitre = state.mitreMapping[ev.id] || 'None';
    const correctMitre = answerKey.mitreMapping[ev.id] || 'N/A';
    const isMitreCorrect = ev.isRelevant ? (userMitre === correctMitre) : 'N/A';

    const row = document.createElement('tr');
    row.innerHTML = `
      <td class="mono text-cyan">${ev.id}</td>
      <td><b>${ev.title}</b></td>
      <td>
        <span class="badge ${isCorrectSelection ? 'badge-available' : 'badge-coming-soon'}">
          ${isSelected ? 'Selected' : 'Excluded'} (${ev.isRelevant ? 'Relevant' : 'Decoy'})
        </span>
      </td>
      <td class="mono">
        ${ev.isRelevant ? `Rank ${userRank + 1} (${isTimelineCorrect ? '✓ Correct' : `Expected Rank ${correctRank + 1}`})` : '—'}
      </td>
      <td class="mono">
        ${ev.isRelevant ? `${userMitre} ${isMitreCorrect ? '✓' : `(Exp: ${correctMitre})`}` : '—'}
      </td>
    `;

    tbody.appendChild(row);
  });
}

function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  
  let icon = 'fa-info-circle';
  if (type === 'success') icon = 'fa-circle-check';
  if (type === 'warn') icon = 'fa-triangle-exclamation';
  if (type === 'danger') icon = 'fa-circle-xmark';

  toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${message}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(50px)';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}
