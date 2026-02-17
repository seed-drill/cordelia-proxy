/**
 * Cordelia Identity Dashboard - Frontend Application
 */

const API_BASE = '';

// DOM Elements
const landingEl = document.getElementById('landing');
const dashboardContainerEl = document.getElementById('dashboard-container');
const loadingEl = document.getElementById('loading');
const errorEl = document.getElementById('error');
const dashboardEl = document.getElementById('dashboard');
const statusLine = document.getElementById('status-line');
const headerActions = document.getElementById('header-actions');

// Content containers
const identityContent = document.getElementById('identity-content');
const activeContent = document.getElementById('active-content');
const prefsContent = document.getElementById('prefs-content');
const delegationContent = document.getElementById('delegation-content');
const refsContent = document.getElementById('refs-content');
const ephemeralContent = document.getElementById('ephemeral-content');
const l2Content = document.getElementById('l2-content');
const networkContent = document.getElementById('network-content');
const groupsContent = document.getElementById('groups-content');

// Auth state
let currentAuth = null;

/**
 * Show landing page
 */
function showLanding() {
  landingEl.style.display = 'block';
  dashboardContainerEl.style.display = 'none';
}

/**
 * Show dashboard container
 */
function showDashboardContainer() {
  landingEl.style.display = 'none';
  dashboardContainerEl.style.display = 'block';
}

/**
 * Show loading state
 */
function showLoading() {
  loadingEl.style.display = 'block';
  errorEl.style.display = 'none';
  dashboardEl.style.display = 'none';
}

/**
 * Show error state
 */
function showError(message) {
  loadingEl.style.display = 'none';
  errorEl.style.display = 'block';
  errorEl.textContent = message;
  dashboardEl.style.display = 'none';
}

/**
 * Show dashboard
 */
function showDashboard() {
  loadingEl.style.display = 'none';
  errorEl.style.display = 'none';
  dashboardEl.style.display = 'block';
}

/**
 * Format date for display
 */
function formatDate(isoString) {
  if (!isoString) return 'N/A';
  const date = new Date(isoString);
  return date.toLocaleDateString('en-GB', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

/**
 * Update header with auth info
 */
function updateHeaderUI(auth) {
  if (!headerActions) return;

  if (auth?.authenticated) {
    // Show user info, user selector, and logout button
    headerActions.innerHTML = `
      <span class="header-user">@${escapeHtml(auth.github_login)}</span>
      <div class="user-selector">
        <label for="user-select">User:</label>
        <select id="user-select">
          <option value="">Loading...</option>
        </select>
      </div>
      <button class="logout-btn" onclick="handleLogout()">Logout</button>
    `;
  } else {
    // Show login button
    headerActions.innerHTML = `
      <a href="/auth/github" class="login-btn-header">Sign in</a>
    `;
  }
}

/**
 * Handle logout
 */
async function handleLogout() {
  try {
    await fetch(`${API_BASE}/auth/logout`, { method: 'POST' });
    window.location.reload();
  } catch (error) {
    console.error('Logout failed:', error);
  }
}

// Make handleLogout available globally for onclick
window.handleLogout = handleLogout;

/**
 * Export user profile - downloads all data as JSON
 */
async function exportProfile() {
  const userSelect = document.getElementById('user-select');
  const userId = userSelect?.value;

  if (!userId) {
    alert('No user selected');
    return;
  }

  try {
    window.open(`${API_BASE}/api/profile/${encodeURIComponent(userId)}/export`, '_blank');
  } catch (error) {
    console.error('Export failed:', error);
    alert('Export failed: ' + error.message);
  }
}

/**
 * Show delete confirmation modal
 */
function showDeleteConfirm() {
  document.getElementById('delete-modal').style.display = 'flex';
}

/**
 * Hide delete confirmation modal
 */
function hideDeleteConfirm() {
  document.getElementById('delete-modal').style.display = 'none';
}

/**
 * Confirm and execute profile deletion
 */
async function confirmDelete() {
  const userSelect = document.getElementById('user-select');
  const userId = userSelect?.value;
  const deleteL2 = document.getElementById('delete-l2-checkbox')?.checked || false;

  if (!userId) {
    alert('No user selected');
    return;
  }

  try {
    const response = await fetch(
      `${API_BASE}/api/profile/${encodeURIComponent(userId)}?deleteL2=${deleteL2}`,
      { method: 'DELETE' }
    );

    const result = await response.json();

    if (response.ok) {
      alert(`Profile deleted. ${result.l2_items_deleted || 0} L2 items removed. Goodbye.`);
      window.location.href = '/';
    } else {
      alert('Delete failed: ' + result.error);
    }
  } catch (error) {
    console.error('Delete failed:', error);
    alert('Delete failed: ' + error.message);
  }

  hideDeleteConfirm();
}

/**
 * Generate new API key for CLI sync
 */
async function generateApiKey() {
  const userSelect = document.getElementById('user-select');
  const userId = userSelect?.value;

  if (!userId) {
    alert('No user selected');
    return;
  }

  const generateBtn = document.getElementById('generate-key-btn');
  generateBtn.disabled = true;
  generateBtn.textContent = 'Generating...';

  try {
    const response = await fetch(`${API_BASE}/api/profile/${encodeURIComponent(userId)}/api-key`, {
      method: 'POST',
    });

    const result = await response.json();

    if (response.ok && result.success) {
      document.getElementById('api-key-value').textContent = result.api_key;
      document.getElementById('api-key-display').style.display = 'block';
      generateBtn.textContent = 'Regenerate API Key';
    } else {
      alert('Failed to generate API key: ' + (result.error || 'Unknown error'));
      generateBtn.textContent = 'Generate New API Key';
    }
  } catch (error) {
    console.error('API key generation failed:', error);
    alert('Failed to generate API key: ' + error.message);
    generateBtn.textContent = 'Generate New API Key';
  }

  generateBtn.disabled = false;
}

/**
 * Copy API key to clipboard
 */
function copyApiKey() {
  const apiKey = document.getElementById('api-key-value').textContent;
  navigator.clipboard.writeText(apiKey).then(() => {
    const copyBtn = document.getElementById('copy-btn');
    copyBtn.textContent = 'Copied!';
    setTimeout(() => {
      copyBtn.textContent = 'Copy to Clipboard';
    }, 2000);
  }).catch(err => {
    console.error('Failed to copy:', err);
    alert('Failed to copy to clipboard');
  });
}

// Make profile functions available globally
window.exportProfile = exportProfile;
window.showDeleteConfirm = showDeleteConfirm;
window.hideDeleteConfirm = hideDeleteConfirm;
window.confirmDelete = confirmDelete;
window.generateApiKey = generateApiKey;
window.copyApiKey = copyApiKey;

/**
 * Check authentication status
 */
async function checkAuth() {
  try {
    const response = await fetch(`${API_BASE}/auth/status`);
    const data = await response.json();
    currentAuth = data;
    return data;
  } catch (error) {
    console.error('Auth check failed:', error);
    return { authenticated: false };
  }
}

// Current identity data (kept in sync for edit mode)
let currentIdentity = null;

/**
 * Render identity card (view mode)
 */
function renderIdentity(identity) {
  currentIdentity = identity;

  const primaryOrg = identity.orgs?.[0];
  const orgDisplay = primaryOrg
    ? `${primaryOrg.role} @ ${primaryOrg.name}`
    : 'No organization';

  const rolesHtml = (identity.roles || [])
    .map(role => `<span class="tag">${escapeHtml(role)}</span>`)
    .join('');

  const githubBadge = identity.github_id
    ? `<span class="tag copper">@${escapeHtml(identity.github_id)}</span>`
    : '';

  const interestsHtml = (identity.interests || [])
    .map(interest => `<span class="tag interest">${escapeHtml(interest)}</span>`)
    .join('');

  const heroesHtml = (identity.heroes || [])
    .map(hero => `<span class="tag hero">${escapeHtml(hero)}</span>`)
    .join('');

  const interestsSection = identity.interests?.length
    ? `<div class="identity-section">
        <span class="section-label">Interests:</span>
        ${interestsHtml}
      </div>`
    : '';

  const heroesSection = identity.heroes?.length
    ? `<div class="identity-section">
        <span class="section-label">Heroes:</span>
        ${heroesHtml}
      </div>`
    : '';

  identityContent.innerHTML = `
    <div class="identity-name">${escapeHtml(identity.name)}</div>
    <div class="identity-org">${escapeHtml(orgDisplay)}</div>
    <div class="identity-roles">${rolesHtml}${githubBadge}</div>
    ${interestsSection}
    ${heroesSection}
    <div class="identity-edit-toolbar">
      <button class="btn btn-secondary" onclick="showIdentityEdit()">Edit</button>
    </div>
  `;
}

/**
 * Show identity edit form
 */
function showIdentityEdit() {
  const id = currentIdentity;
  if (!id) return;

  identityContent.innerHTML = `
    <div class="identity-edit-form">
      <div class="edit-field">
        <label for="edit-name">Name</label>
        <input type="text" id="edit-name" value="${escapeHtml(id.name || '')}" />
      </div>
      <div class="edit-field">
        <label for="edit-github">GitHub ID</label>
        <input type="text" id="edit-github" value="${escapeHtml(id.github_id || '')}" />
      </div>
      <div class="edit-field">
        <label for="edit-tz">Timezone</label>
        <input type="text" id="edit-tz" value="${escapeHtml(id.tz || '')}" placeholder="e.g. Europe/London" />
      </div>
      <div class="edit-field">
        <label for="edit-interests">Interests <span class="edit-hint">comma-separated</span></label>
        <input type="text" id="edit-interests" value="${escapeHtml((id.interests || []).join(', '))}" placeholder="e.g. distributed systems, music" />
      </div>
      <div class="edit-field">
        <label for="edit-heroes">Heroes <span class="edit-hint">comma-separated</span></label>
        <input type="text" id="edit-heroes" value="${escapeHtml((id.heroes || []).join(', '))}" placeholder="e.g. Alan Turing, Grace Hopper" />
      </div>
      <div class="edit-actions">
        <button class="btn btn-primary" onclick="saveIdentity()">Save</button>
        <button class="btn btn-secondary" onclick="cancelIdentityEdit()">Cancel</button>
      </div>
    </div>
  `;
  document.getElementById('edit-name').focus();
}

/**
 * Cancel identity edit, return to view mode
 */
function cancelIdentityEdit() {
  if (currentIdentity) renderIdentity(currentIdentity);
}

/**
 * Parse comma-separated string into trimmed array, filtering empty strings
 */
function parseCommaSeparated(value) {
  return value.split(',').map(s => s.trim()).filter(s => s.length > 0);
}

/**
 * Save identity edits via read-modify-write on full L1 context
 */
async function saveIdentity() {
  const userSelect = document.getElementById('user-select');
  const userId = userSelect?.value;
  if (!userId) { alert('No user selected'); return; }

  const name = document.getElementById('edit-name').value.trim();
  if (!name) { alert('Name is required'); return; }

  try {
    // Read current full L1 context
    const getRes = await fetch(`${API_BASE}/api/hot/${encodeURIComponent(userId)}`);
    if (!getRes.ok) throw new Error('Failed to read current profile');
    const context = await getRes.json();

    // Update identity fields
    context.identity.name = name;
    context.identity.github_id = document.getElementById('edit-github').value.trim() || undefined;
    context.identity.tz = document.getElementById('edit-tz').value.trim() || undefined;
    context.identity.interests = parseCommaSeparated(document.getElementById('edit-interests').value);
    context.identity.heroes = parseCommaSeparated(document.getElementById('edit-heroes').value);

    // Update timestamp
    context.updated_at = new Date().toISOString();

    // Write back
    const putRes = await fetch(`${API_BASE}/api/hot/${encodeURIComponent(userId)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(context),
    });

    if (!putRes.ok) {
      const err = await putRes.json();
      throw new Error(err.error || putRes.statusText);
    }

    // Re-render with updated data
    renderIdentity(context.identity);
  } catch (error) {
    console.error('Save identity failed:', error);
    alert('Failed to save: ' + error.message);
  }
}

// Make identity edit functions available globally
window.showIdentityEdit = showIdentityEdit;
window.cancelIdentityEdit = cancelIdentityEdit;
window.saveIdentity = saveIdentity;

/**
 * Render active state card
 */
function renderActiveState(active) {
  const nextItems = (active.next || [])
    .map(item => `<li>${escapeHtml(item)}</li>`)
    .join('');

  activeContent.innerHTML = `
    <div class="active-field">
      <div class="active-label">Project</div>
      <div class="active-value">${escapeHtml(active.project || 'None')}</div>
    </div>
    <div class="active-field">
      <div class="active-label">Sprint</div>
      <div class="active-value">${active.sprint ?? 'N/A'}</div>
    </div>
    <div class="active-field">
      <div class="active-label">Focus</div>
      <div class="active-value">${escapeHtml(active.focus || 'None')}</div>
    </div>
    <div class="active-field">
      <div class="active-label">Next Actions</div>
      <ul class="next-list">${nextItems || '<li>None</li>'}</ul>
    </div>
  `;
}

/**
 * Render preferences card
 */
function renderPreferences(prefs) {
  const boolValue = (val) => val
    ? '<span class="pref-value yes">Yes</span>'
    : '<span class="pref-value no">No</span>';

  prefsContent.innerHTML = `
    <div class="pref-grid">
      <div class="pref-item">
        <span class="pref-label">Planning</span>
        <span class="pref-value">${escapeHtml(prefs.planning_mode)}</span>
      </div>
      <div class="pref-item">
        <span class="pref-label">Verbosity</span>
        <span class="pref-value">${escapeHtml(prefs.verbosity)}</span>
      </div>
      <div class="pref-item">
        <span class="pref-label">Feedback</span>
        <span class="pref-value">${escapeHtml(prefs.feedback_style)}</span>
      </div>
      <div class="pref-item">
        <span class="pref-label">Emoji</span>
        ${boolValue(prefs.emoji)}
      </div>
      <div class="pref-item">
        <span class="pref-label">Proactive</span>
        ${boolValue(prefs.proactive_suggestions)}
      </div>
      <div class="pref-item">
        <span class="pref-label">Auto-commit</span>
        ${boolValue(prefs.auto_commit)}
      </div>
    </div>
  `;
}

/**
 * Render delegation card
 */
function renderDelegation(delegation) {
  const requireItems = (delegation.require_approval || [])
    .map(item => `<span class="delegation-item">${escapeHtml(item)}</span>`)
    .join('');

  const autoItems = (delegation.autonomous || [])
    .map(item => `<span class="delegation-item">${escapeHtml(item)}</span>`)
    .join('');

  delegationContent.innerHTML = `
    <div class="delegation-status">
      <div class="delegation-stat">
        <span class="label">Allowed:</span>
        <span class="value">${delegation.allowed ? 'Yes' : 'No'}</span>
      </div>
      <div class="delegation-stat">
        <span class="label">Max parallel:</span>
        <span class="value">${delegation.max_parallel}</span>
      </div>
    </div>
    <div class="delegation-list-section">
      <h3>Require Approval</h3>
      <div class="delegation-list">${requireItems || '<span class="delegation-item">None</span>'}</div>
    </div>
    <div class="delegation-list-section">
      <h3>Autonomous</h3>
      <div class="delegation-list">${autoItems || '<span class="delegation-item">None</span>'}</div>
    </div>
  `;
}

/**
 * Render key references card
 */
function renderKeyRefs(identity) {
  const refs = identity.key_refs || [];
  const refsHtml = refs
    .map(ref => `<span class="ref-item">${escapeHtml(ref)}</span>`)
    .join('');

  refsContent.innerHTML = `
    <div class="refs-grid">${refsHtml || '<span class="ref-item">None defined</span>'}</div>
  `;
}

/**
 * Format datetime for display
 */
function formatDateTime(isoString) {
  if (!isoString) return 'N/A';
  const date = new Date(isoString);
  return date.toLocaleString('en-GB', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

/**
 * Render ephemeral/session continuity card
 */
function renderEphemeral(ephemeral, updatedAt) {
  if (!ephemeral) {
    ephemeralContent.innerHTML = '<p>No session continuity data available</p>';
    return;
  }

  const vesselHtml = ephemeral.vessel
    ? `<div class="ephemeral-vessel">${escapeHtml(ephemeral.vessel)}</div>`
    : '';

  const summaryHtml = ephemeral.last_summary
    ? `
      <div class="ephemeral-summary">
        <div class="ephemeral-summary-label">Last Session Summary</div>
        ${escapeHtml(ephemeral.last_summary)}
      </div>
    `
    : '';

  const chainHash = ephemeral.integrity?.chain_hash || 'N/A';
  const shortHash = chainHash.length > 16 ? chainHash.substring(0, 8) + '...' + chainHash.substring(chainHash.length - 8) : chainHash;
  const lastSyncCheck = ephemeral.last_sync_check || updatedAt;

  ephemeralContent.innerHTML = `
    <div class="ephemeral-stats">
      <div class="ephemeral-stat">
        <span class="label">Sessions:</span>
        <span class="value">${ephemeral.session_count}</span>
      </div>
      <div class="ephemeral-stat">
        <span class="label">Genesis:</span>
        <span class="value">${formatDate(ephemeral.integrity?.genesis)}</span>
      </div>
      <div class="ephemeral-stat">
        <span class="label">Last session:</span>
        <span class="value">${formatDate(ephemeral.last_session_end)}</span>
      </div>
    </div>
    <div class="sync-status">
      <div class="sync-stat">
        <span class="label">Last Sync Check:</span>
        <span class="value">${formatDateTime(lastSyncCheck)}</span>
      </div>
      <div class="sync-stat">
        <span class="label">Content Updated:</span>
        <span class="value">${formatDateTime(updatedAt)}</span>
      </div>
      <div class="sync-stat">
        <span class="label">Chain Hash:</span>
        <span class="value hash" title="${escapeHtml(chainHash)}">${escapeHtml(shortHash)}</span>
      </div>
    </div>
    ${vesselHtml}
    ${summaryHtml}
  `;
}

/**
 * Render L2 memory summary card
 */
function renderL2Summary(l2Index) {
  const entries = l2Index.entries || [];
  const entities = entries.filter(e => e.type === 'entity');
  const sessions = entries.filter(e => e.type === 'session');
  const learnings = entries.filter(e => e.type === 'learning');

  // Get 10 most recent items
  const recent = [...entries].slice(0, 10);
  const recentHtml = recent.map(item => {
    const isLearning = item.type === 'learning' ? 'learning' : '';
    const typeClass = item.type === 'session' ? 'session' : isLearning;
    return `
      <div class="l2-item">
        <span class="l2-item-type ${typeClass}">${item.type}</span>
        <span class="l2-item-name">${escapeHtml(item.name)}</span>
      </div>
    `;
  }).join('');

  l2Content.innerHTML = `
    <div class="l2-stats">
      <div class="l2-stat">
        <div class="count">${entities.length}</div>
        <div class="label">Entities</div>
      </div>
      <div class="l2-stat">
        <div class="count">${sessions.length}</div>
        <div class="label">Sessions</div>
      </div>
      <div class="l2-stat">
        <div class="count">${learnings.length}</div>
        <div class="label">Learnings</div>
      </div>
    </div>
    <div class="l2-recent">
      <h3>Recent Items</h3>
      <div class="l2-list">${recentHtml || '<p>No items yet</p>'}</div>
    </div>
  `;
}

/**
 * Format seconds as "Xd Xh Xm"
 */
function formatUptime(secs) {
  if (!secs && secs !== 0) return 'N/A';
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const parts = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0 || d > 0) parts.push(`${h}h`);
  parts.push(`${m}m`);
  return parts.join(' ');
}

/**
 * Render Network Health panel content
 */
function renderNetworkHealth(status, diagnostics) {
  if (!status || !status.connected) {
    const errorMsg = status?.error || 'Core node not reachable';
    networkContent.innerHTML = `
      <div class="network-grid">
        <div class="network-stat" style="grid-column: 1 / -1;">
          <div class="status-indicator">
            <span class="status-dot offline"></span>
            <span>Node not connected</span>
          </div>
          <div class="network-stat-value" style="margin-top: 0.5rem; font-size: 0.85rem; color: var(--color-muted);">${escapeHtml(errorMsg)}</div>
        </div>
      </div>
      <div class="network-footer">Last checked: ${new Date().toLocaleTimeString('en-GB')}</div>
    `;
    return;
  }

  const nodeId = status.node_id || 'N/A';
  const shortNodeId = nodeId.length > 16 ? nodeId.substring(0, 8) + '...' + nodeId.substring(nodeId.length - 8) : nodeId;
  const entityId = status.entity_id || 'N/A';
  const peers = status.peers || {};
  const groups = status.groups || [];

  // Diagnostics may not be available
  const repl = diagnostics?.replication || {};
  const storage = diagnostics?.storage || {};

  networkContent.innerHTML = `
    <div class="network-grid">
      <div class="network-stat">
        <h3>Node Status</h3>
        <div class="status-indicator">
          <span class="status-dot online"></span>
          <span>Connected</span>
        </div>
        <div class="network-stat-row"><span class="label">Node ID:</span> <span class="value hash" title="${escapeHtml(nodeId)}">${escapeHtml(shortNodeId)}</span></div>
        <div class="network-stat-row"><span class="label">Entity:</span> <span class="value">${escapeHtml(entityId)}</span></div>
        <div class="network-stat-row"><span class="label">Uptime:</span> <span class="value">${formatUptime(status.uptime_secs)}</span></div>
      </div>
      <div class="network-stat">
        <h3>Peers</h3>
        <div class="network-stat-row"><span class="label">Warm:</span> <span class="value">${peers.warm ?? 0}</span></div>
        <div class="network-stat-row"><span class="label">Hot:</span> <span class="value">${peers.hot ?? 0}</span></div>
        <div class="network-stat-row"><span class="label">Total:</span> <span class="value">${peers.total ?? 0}</span></div>
      </div>
      <div class="network-stat">
        <h3>Replication</h3>
        <div class="network-stat-row"><span class="label">Pushed:</span> <span class="value">${repl.items_pushed ?? '-'}</span></div>
        <div class="network-stat-row"><span class="label">Synced:</span> <span class="value">${repl.items_synced ?? '-'}</span></div>
        <div class="network-stat-row"><span class="label">Errors:</span> <span class="value">${repl.sync_errors ?? '-'}</span></div>
        <div class="network-stat-row"><span class="label">Sync rounds:</span> <span class="value">${repl.sync_rounds ?? '-'}</span></div>
      </div>
      <div class="network-stat">
        <h3>Storage</h3>
        <div class="network-stat-row"><span class="label">Items:</span> <span class="value">${storage.l2_items ?? '-'}</span></div>
        <div class="network-stat-row"><span class="label">Size:</span> <span class="value">${storage.l2_data_bytes ? (storage.l2_data_bytes / (1024 * 1024)).toFixed(1) + ' MB' : '-'}</span></div>
        <div class="network-stat-row"><span class="label">Groups:</span> <span class="value">${groups.length}</span></div>
      </div>
    </div>
    <div class="network-footer">Last checked: ${new Date().toLocaleTimeString('en-GB')}</div>
  `;
}

/**
 * Load network health data from core node APIs
 */
async function loadNetworkHealth() {
  try {
    const [statusRes, diagRes] = await Promise.all([
      fetch(`${API_BASE}/api/core/status`),
      fetch(`${API_BASE}/api/core/diagnostics`),
    ]);
    const status = await statusRes.json();
    const diagnostics = diagRes.ok ? await diagRes.json() : null;
    renderNetworkHealth(status, diagnostics);
  } catch (error) {
    console.error('Network health fetch error:', error);
    renderNetworkHealth(null, null);
  }
}

/**
 * Render groups table
 */
function renderGroups(groups, peers) {
  const userId = currentAuth?.cordelia_user;

  // Build a map: groupId -> list of peers that have this group
  const peersByGroup = {};
  if (peers && peers.length > 0) {
    for (const peer of peers) {
      const peerGroups = peer.groups || [];
      const shortId = peer.node_id ? peer.node_id.substring(0, 12) + '...' : '?';
      const stateClass = peer.state === 'hot' ? 'peer-hot' : 'peer-warm';
      for (const gid of peerGroups) {
        if (!peersByGroup[gid]) peersByGroup[gid] = [];
        peersByGroup[gid].push({ shortId, fullId: peer.node_id, state: peer.state, stateClass });
      }
    }
  }

  if (!groups || groups.length === 0) {
    groupsContent.innerHTML = `
      <p style="color: var(--color-muted); margin-bottom: 0.5rem;">No groups yet.</p>
      <div class="groups-toolbar">
        <button class="btn btn-primary" onclick="showCreateGroupForm()">Create Group</button>
      </div>
    `;
    return;
  }

  const rowsHtml = groups.map(group => {
    const members = group.members || [];
    const myMembership = userId ? members.find(m => m.entity_id === userId) : null;
    const myRole = myMembership ? myMembership.role : null;

    // Members display
    const membersHtml = members.map(m => {
      const roleClass = `role-${m.role}`;
      return `<span class="member-chip">${escapeHtml(m.entity_id)} <span class="role-tag ${roleClass}">${m.role}</span></span>`;
    }).join('');

    // Peers display
    const groupPeers = peersByGroup[group.id] || [];
    const peersHtml = groupPeers.length > 0
      ? groupPeers.map(p =>
          `<span class="peer-chip ${p.stateClass}" title="${escapeHtml(p.fullId)}">${escapeHtml(p.shortId)} <span class="peer-state">${p.state}</span></span>`
        ).join('')
      : '<span style="color: var(--color-muted); font-size: 0.8rem;">Local only</span>';

    // Culture display
    let cultureDisplay = '';
    if (group.culture) {
      try {
        const c = typeof group.culture === 'string' ? JSON.parse(group.culture) : group.culture;
        cultureDisplay = escapeHtml(c.broadcast_eagerness || JSON.stringify(c));
      } catch {
        cultureDisplay = escapeHtml(String(group.culture));
      }
    }

    // Role display
    const roleHtml = myRole
      ? `<span class="role-tag role-${myRole}">${myRole}</span>`
      : '<span style="color: var(--color-muted);">\u2014</span>';

    // Actions
    let actionsHtml = '';
    if (!myRole) {
      actionsHtml += `<button class="btn-join" onclick="joinGroup('${escapeHtml(group.id)}')">Join</button>`;
    } else {
      actionsHtml += `<button class="btn-leave" onclick="leaveGroup('${escapeHtml(group.id)}')">Leave</button>`;
    }
    if (myRole === 'owner') {
      actionsHtml += `<button class="btn-delete-group" onclick="deleteGroup('${escapeHtml(group.id)}')">Delete</button>`;
    }

    return `
      <tr>
        <td><strong>${escapeHtml(group.name)}</strong><br><span style="font-size: 0.8rem; color: var(--color-muted);">${escapeHtml(group.id)}</span></td>
        <td><div class="member-list">${membersHtml || '<span style="color: var(--color-muted);">None</span>'}</div></td>
        <td><div class="peer-list">${peersHtml}</div></td>
        <td>${cultureDisplay || '<span style="color: var(--color-muted);">\u2014</span>'}</td>
        <td>${roleHtml}</td>
        <td><div class="actions-cell">${actionsHtml}</div></td>
      </tr>
    `;
  }).join('');

  groupsContent.innerHTML = `
    <table class="groups-table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Members</th>
          <th>Peers</th>
          <th>Culture</th>
          <th>Your Role</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>${rowsHtml}</tbody>
    </table>
    <div class="groups-toolbar">
      <button class="btn btn-primary" onclick="showCreateGroupForm()">Create Group</button>
    </div>
  `;
}

/**
 * Load groups from API and render
 */
async function loadGroups() {
  try {
    const [groupsRes, peersRes] = await Promise.all([
      fetch(`${API_BASE}/api/groups`),
      fetch(`${API_BASE}/api/peers`).catch(() => null),
    ]);
    if (!groupsRes.ok) throw new Error(`Failed to load groups: ${groupsRes.statusText}`);
    const groupsData = await groupsRes.json();
    const peersData = peersRes && peersRes.ok ? await peersRes.json() : null;
    renderGroups(groupsData.groups || [], peersData?.peers || []);
  } catch (error) {
    console.error('Error loading groups:', error);
    groupsContent.innerHTML = `<p style="color: #dc3545;">Failed to load groups: ${escapeHtml(error.message)}</p>`;
  }
}

/**
 * Join a group
 */
async function joinGroup(groupId) {
  const entityId = currentAuth?.cordelia_user;
  if (!entityId) { alert('No user authenticated'); return; }

  try {
    const response = await fetch(`${API_BASE}/api/groups/${encodeURIComponent(groupId)}/members`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entity_id: entityId }),
    });
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || response.statusText);
    }
    await loadGroups();
  } catch (error) {
    console.error('Join group failed:', error);
    alert('Failed to join group: ' + error.message);
  }
}

/**
 * Leave a group
 */
async function leaveGroup(groupId) {
  const entityId = currentAuth?.cordelia_user;
  if (!entityId) { alert('No user authenticated'); return; }

  try {
    const response = await fetch(
      `${API_BASE}/api/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(entityId)}`,
      { method: 'DELETE' }
    );
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || response.statusText);
    }
    await loadGroups();
  } catch (error) {
    console.error('Leave group failed:', error);
    alert('Failed to leave group: ' + error.message);
  }
}

/**
 * Delete a group (with confirmation)
 */
async function deleteGroup(groupId) {
  if (!confirm(`Delete group "${groupId}"? This cannot be undone.`)) return;

  try {
    const response = await fetch(`${API_BASE}/api/groups/${encodeURIComponent(groupId)}`, {
      method: 'DELETE',
    });
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || response.statusText);
    }
    await loadGroups();
  } catch (error) {
    console.error('Delete group failed:', error);
    alert('Failed to delete group: ' + error.message);
  }
}

/**
 * Show the create group inline form
 */
function showCreateGroupForm() {
  document.getElementById('groups-create-form').style.display = 'block';
  document.getElementById('group-id-input').focus();
}

/**
 * Hide the create group inline form
 */
function hideCreateGroupForm() {
  document.getElementById('groups-create-form').style.display = 'none';
  document.getElementById('group-id-input').value = '';
  document.getElementById('group-name-input').value = '';
}

/**
 * Submit the create group form
 */
async function submitCreateGroup() {
  const id = document.getElementById('group-id-input').value.trim();
  const name = document.getElementById('group-name-input').value.trim();
  const entityId = currentAuth?.cordelia_user;

  if (!id || !name) { alert('Both ID and Name are required'); return; }

  try {
    const response = await fetch(`${API_BASE}/api/groups`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id, name, entity_id: entityId }),
    });
    if (!response.ok) {
      const err = await response.json();
      throw new Error(err.error || response.statusText);
    }
    hideCreateGroupForm();
    await loadGroups();
  } catch (error) {
    console.error('Create group failed:', error);
    alert('Failed to create group: ' + error.message);
  }
}

// Make groups functions available globally
window.joinGroup = joinGroup;
window.leaveGroup = leaveGroup;
window.deleteGroup = deleteGroup;
window.showCreateGroupForm = showCreateGroupForm;
window.hideCreateGroupForm = hideCreateGroupForm;
window.submitCreateGroup = submitCreateGroup;

/**
 * Load and display data for a user
 */
async function loadUserData(userId) {
  showLoading();

  try {
    // Fetch L1 hot context and L2 index in parallel
    const [hotResponse, l2Response] = await Promise.all([
      fetch(`${API_BASE}/api/hot/${userId}`),
      fetch(`${API_BASE}/api/l2/index`),
    ]);

    if (!hotResponse.ok) {
      throw new Error(`Failed to load user data: ${hotResponse.statusText}`);
    }

    const hotData = await hotResponse.json();
    const l2Data = await l2Response.json();

    // Render all cards
    renderIdentity(hotData.identity);
    renderActiveState(hotData.active);
    renderPreferences(hotData.prefs);
    renderDelegation(hotData.delegation);
    renderKeyRefs(hotData.identity);
    renderEphemeral(hotData.ephemeral, hotData.updated_at);
    renderL2Summary(l2Data);

    // Load groups (independent of L1 data)
    loadGroups();

    // Update status line
    statusLine.textContent = `Updated: ${hotData.updated_at} | Version: ${hotData.version}`;

    showDashboard();
  } catch (error) {
    console.error('Error loading user data:', error);
    showError(`Failed to load data: ${error.message}. Make sure the HTTP server is running.`);
  }
}

/**
 * Load available users and populate selector
 */
async function loadUsers() {
  const userSelect = document.getElementById('user-select');
  if (!userSelect) return;

  try {
    const response = await fetch(`${API_BASE}/api/users`);
    if (!response.ok) {
      throw new Error('Failed to fetch users');
    }

    const data = await response.json();
    const users = data.users || [];

    userSelect.innerHTML = users.length
      ? users.map(u => `<option value="${escapeHtml(u)}">${escapeHtml(u)}</option>`).join('')
      : '<option value="">No users found</option>';

    // If authenticated and linked to a Cordelia user, select that user
    // Otherwise, prefer russell, then first user
    let defaultUser;
    if (currentAuth?.authenticated && currentAuth?.cordelia_user) {
      defaultUser = currentAuth.cordelia_user;
    } else if (users.includes('russell')) {
      defaultUser = 'russell';
    } else if (users.length > 0) {
      defaultUser = users[0];
    }

    if (defaultUser) {
      userSelect.value = defaultUser;
      loadUserData(defaultUser);
    }

    // Add change listener
    userSelect.addEventListener('change', (e) => {
      const userId = e.target.value;
      if (userId) {
        loadUserData(userId);
      }
    });
  } catch (error) {
    console.error('Error loading users:', error);
    userSelect.innerHTML = '<option value="">Error loading users</option>';
    showError(`Failed to connect to API: ${error.message}. Make sure the HTTP server is running on ${API_BASE || 'localhost:3847'}.`);
  }
}

/**
 * Initialize dashboard
 */
async function init() {
  // Check auth status
  const auth = await checkAuth();

  // Update header UI based on auth state
  updateHeaderUI(auth);

  if (auth?.authenticated) {
    // Check if user has a Cordelia profile
    if (!auth.cordelia_user) {
      // No profile yet - redirect to genesis mode
      window.location.href = '/genesis.html';
      return;
    }
    // Show dashboard for authenticated users with profiles
    showDashboardContainer();
    // Load users and data
    loadUsers();
    // Start network health and groups polling
    loadNetworkHealth();
    setInterval(loadNetworkHealth, 30000);
    setInterval(loadGroups, 30000);
  } else {
    // Show landing page for unauthenticated users
    showLanding();
  }
}

// Initialize on load
document.addEventListener('DOMContentLoaded', init);
