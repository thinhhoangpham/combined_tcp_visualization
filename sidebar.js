// Sidebar logic for IP Connection Analysis
// This file contains all logic for the sidebar UI and its event handlers
import { getFlowColors, getInvalidLabels, getInvalidReason, getFlowColor } from './legends.js';
import { MAX_FLOW_LIST_ITEMS, FLOW_LIST_RENDER_BATCH } from './config.js';

export function initSidebar(options) {
    // options: { onResetView, ... }
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;

    const desiredWidth = 340; // px

    // Ensure sidebar fills viewport and scrolls
    sidebar.style.position = 'fixed';
    sidebar.style.top = '0';
    sidebar.style.right = '0';
    sidebar.style.height = '100vh';
    sidebar.style.overflowY = 'auto';
    sidebar.style.width = `${desiredWidth}px`;
    sidebar.style.boxSizing = 'border-box';
    sidebar.style.background = '#fff';
    sidebar.style.borderLeft = '1px solid #e6e6e6';
    sidebar.style.display = 'flex';
    sidebar.style.flexDirection = 'column';
    sidebar.style.zIndex = '100';
    // Leave space for fixed footer button
    sidebar.style.paddingBottom = '72px';

    // Push main content so it doesn't hide behind fixed sidebar
    const applyBodyPadding = () => {
        document.body.style.paddingRight = `${sidebar.getBoundingClientRect().width}px`;
    };
    applyBodyPadding();
    window.addEventListener('resize', applyBodyPadding);

    // Make Reset View button sticky at the bottom
    const resetBtn = document.getElementById('resetView');
    if (resetBtn) {
        // Fix to viewport bottom aligned with sidebar
        resetBtn.style.position = 'fixed';
        resetBtn.style.right = '0';
        resetBtn.style.bottom = '0';
        resetBtn.style.width = `${desiredWidth}px`;
        resetBtn.style.zIndex = '110';
        resetBtn.style.background = '#fff';
        resetBtn.style.borderTop = '1px solid #eee';
        resetBtn.style.padding = '12px 0';
        resetBtn.style.margin = '0';
        resetBtn.style.display = 'block';
        resetBtn.style.textAlign = 'center';
        if (options && typeof options.onResetView === 'function') {
            resetBtn.onclick = options.onResetView;
        }
    }
}

// Sidebar render and update helpers (moved from main file)
export function createIPCheckboxes(uniqueIPs, onChange) {
    const container = document.getElementById('ipCheckboxes');
    if (!container) return;
    container.innerHTML = '';
    uniqueIPs.forEach(ip => {
        const div = document.createElement('div');
        div.style.marginBottom = '5px';
        div.className = 'ip-item';
        div.dataset.ip = ip;
        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.id = `ip-${ip.replace(/\./g, '-')}`;
        checkbox.value = ip;
        checkbox.checked = false;
        if (typeof onChange === 'function') {
            checkbox.addEventListener('change', onChange);
        }
        const label = document.createElement('label');
        label.htmlFor = checkbox.id;
        label.textContent = ip;
        label.style.marginLeft = '5px';
        label.style.fontSize = '12px';
        label.style.cursor = 'pointer';
        div.appendChild(checkbox);
        div.appendChild(label);
        container.appendChild(div);
    });
}

export function filterIPList(searchTerm) {
    document.querySelectorAll('.ip-item').forEach(item => {
        const ip = item.dataset.ip || '';
        const matches = ip.toLowerCase().includes((searchTerm || '').toLowerCase());
        item.style.display = matches ? 'block' : 'none';
    });
}

export function filterFlowList(searchTerm) {
    const items = document.querySelectorAll('#flowList .flow-item');
    const term = (searchTerm || '').toLowerCase();
    items.forEach(item => {
        const text = (item.innerText || item.textContent || '').toLowerCase();
        item.style.display = text.includes(term) ? '' : 'none';
    });
}

// Progress UI for flow processing/list rendering
export function showFlowProgress(label = 'Working…', percent = 0) {
    const box = document.getElementById('flowProgress');
    const bar = document.getElementById('flowProgressBar');
    const lbl = document.getElementById('flowProgressLabel');
    if (!box || !bar || !lbl) return;
    box.style.display = 'block';
    lbl.textContent = label;
    const pct = Math.max(0, Math.min(1, Number(percent) || 0));
    bar.style.width = `${Math.round(pct * 100)}%`;
}

export function updateFlowProgress(percent, label) {
    const bar = document.getElementById('flowProgressBar');
    if (!bar) return;
    if (label) {
        const lbl = document.getElementById('flowProgressLabel');
        if (lbl) lbl.textContent = label;
    }
    const pct = Math.max(0, Math.min(1, Number(percent) || 0));
    bar.style.width = `${Math.round(pct * 100)}%`;
}

export function hideFlowProgress() {
    const box = document.getElementById('flowProgress');
    if (!box) return;
    box.style.display = 'none';
}

// CSV loading progress UI
export function showCsvProgress(label = 'Loading CSV file...', percent = 0) {
    const box = document.getElementById('csvProgress');
    const bar = document.getElementById('csvProgressBar');
    const lbl = document.getElementById('csvProgressLabel');
    if (!box || !bar || !lbl) return;
    box.style.display = 'block';
    lbl.textContent = label;
    const pct = Math.max(0, Math.min(1, Number(percent) || 0));
    bar.style.width = `${Math.round(pct * 100)}%`;
}

export function updateCsvProgress(percent, label) {
    const bar = document.getElementById('csvProgressBar');
    if (!bar) return;
    if (label) {
        const lbl = document.getElementById('csvProgressLabel');
        if (lbl) lbl.textContent = label;
    }
    const pct = Math.max(0, Math.min(1, Number(percent) || 0));
    bar.style.width = `${Math.round(pct * 100)}%`;
}

export function hideCsvProgress() {
    const box = document.getElementById('csvProgress');
    if (!box) return;
    box.style.display = 'none';
}

// Paginated flow list rendering
// hasPacketData: if false, disables "Export CSV" and "View Packets" buttons (flow_list.json mode)
export function createFlowListCapped(flows, selectedFlowIds, formatBytes, formatTimestamp, exportFlowToCSV, zoomToFlow, updateTcpFlowPacketsGlobal, flowColors = {}, enterFlowDetailMode = null, hasPacketData = true) {
    const container = document.getElementById('flowListModalList') || document.getElementById('flowList');
    if (!container) return;
    if (!flows || flows.length === 0) {
        container.innerHTML = '<div style="color:#666; text-align:center; padding:20px;">No flows to display</div>';
        return;
    }

    // Sort flows
    const sorted = [...flows].sort((a, b) => a.startTime - b.startTime);
    const total = sorted.length;
    const flowsPerPage = MAX_FLOW_LIST_ITEMS || 500;
    const totalPages = Math.ceil(total / flowsPerPage);

    // Store pagination state on container
    if (!container._paginationState) {
        container._paginationState = {
            currentPage: 1,
            totalPages: totalPages,
            flows: sorted,
            flowsPerPage: flowsPerPage
        };
    } else {
        // Update state with new flows
        container._paginationState.flows = sorted;
        container._paginationState.totalPages = totalPages;
        container._paginationState.flowsPerPage = flowsPerPage;
        // Reset to page 1 if current page is beyond new total
        if (container._paginationState.currentPage > totalPages) {
            container._paginationState.currentPage = 1;
        }
    }

    const state = container._paginationState;
    const startIndex = (state.currentPage - 1) * flowsPerPage;
    const endIndex = Math.min(startIndex + flowsPerPage, total);
    const currentPageFlows = sorted.slice(startIndex, endIndex);

    // Clear container and create pagination UI
    container.innerHTML = '';
    
    // Create pagination header
    const paginationHeader = document.createElement('div');
    paginationHeader.style.cssText = 'display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; padding:8px; background:#f8f9fa; border-radius:4px; font-size:12px;';
    
    const pageInfo = document.createElement('div');
    pageInfo.style.cssText = 'color:#555;';
    pageInfo.innerHTML = `Page ${state.currentPage} of ${totalPages} • Showing ${(startIndex + 1).toLocaleString()}-${endIndex.toLocaleString()} of ${total.toLocaleString()} flows`;
    
    const paginationControls = document.createElement('div');
    paginationControls.style.cssText = 'display:flex; gap:8px; align-items:center;';
    
    // Previous button
    const prevBtn = document.createElement('button');
    prevBtn.textContent = '← Previous';
    prevBtn.disabled = state.currentPage === 1;
    prevBtn.style.cssText = 'padding:4px 8px; border:1px solid #ced4da; border-radius:3px; background:#fff; cursor:pointer; font-size:11px;';
    if (prevBtn.disabled) prevBtn.style.opacity = '0.5';
    
    // Page selector
    const pageSelect = document.createElement('select');
    pageSelect.style.cssText = 'padding:4px; border:1px solid #ced4da; border-radius:3px; font-size:11px;';
    for (let i = 1; i <= totalPages; i++) {
        const option = document.createElement('option');
        option.value = i;
        option.textContent = i;
        if (i === state.currentPage) option.selected = true;
        pageSelect.appendChild(option);
    }
    
    // Next button
    const nextBtn = document.createElement('button');
    nextBtn.textContent = 'Next →';
    nextBtn.disabled = state.currentPage === totalPages;
    nextBtn.style.cssText = 'padding:4px 8px; border:1px solid #ced4da; border-radius:3px; background:#fff; cursor:pointer; font-size:11px;';
    if (nextBtn.disabled) nextBtn.style.opacity = '0.5';
    
    // Event handlers
    const renderPage = (page) => {
        state.currentPage = page;
        createFlowListCapped(flows, selectedFlowIds, formatBytes, formatTimestamp, exportFlowToCSV, zoomToFlow, updateTcpFlowPacketsGlobal, flowColors, enterFlowDetailMode, hasPacketData);
    };
    
    prevBtn.addEventListener('click', () => {
        if (state.currentPage > 1) renderPage(state.currentPage - 1);
    });
    
    nextBtn.addEventListener('click', () => {
        if (state.currentPage < totalPages) renderPage(state.currentPage + 1);
    });
    
    pageSelect.addEventListener('change', (e) => {
        renderPage(parseInt(e.target.value));
    });
    
    paginationControls.appendChild(prevBtn);
    paginationControls.appendChild(pageSelect);
    paginationControls.appendChild(nextBtn);
    
    paginationHeader.appendChild(pageInfo);
    paginationHeader.appendChild(paginationControls);
    container.appendChild(paginationHeader);

    const invalidLabels = getInvalidLabels();

    // Render current page flows
    const BATCH = Math.max(50, Number(FLOW_LIST_RENDER_BATCH) || 200);
    const shouldShowProgress = currentPageFlows.length >= BATCH * 2;
    if (shouldShowProgress) {
        showFlowProgress('Rendering flow list…', 0);
    }

    let index = 0;
    function renderBatch() {
        const end = Math.min(currentPageFlows.length, index + BATCH);
        for (let i = index; i < end; i++) {
            const flow = currentPageFlows[i];
            const duration = Math.max(0, Math.round((flow.endTime - flow.startTime) / 1000000));
            const { utcTime: startTime } = formatTimestamp(flow.startTime);
            const { utcTime: endTime } = formatTimestamp(flow.endTime);
            const reason = getInvalidReason(flow);
            const color = getFlowColor(flow, flowColors);

            let closeTypeText = '';
            if (reason) {
                const label = invalidLabels[reason] || 'Invalid';
                closeTypeText = `
                    <span style="display:inline-flex; align-items:center; gap:6px;">
                        <span style=\"display:inline-block; width:10px; height:10px; border-radius:2px; background:${color}; border:1px solid #fff; box-shadow:0 0 0 1px rgba(0,0,0,0.08);\"></span>
                        <span style=\"color:#333;\">${label}</span>
                    </span>`;
            } else if (flow.closeType === 'graceful' || flow.closeType === 'abortive') {
                const label = flow.closeType === 'graceful' ? 'Graceful close' : 'Abortive close';
                closeTypeText = `
                    <span style="display:inline-flex; align-items:center; gap:6px;">
                        <span style=\"display:inline-block; width:10px; height:10px; border-radius:2px; background:${color}; border:1px solid #fff; box-shadow:0 0 0 1px rgba(0,0,0,0.08);\"></span>
                        <span style=\"color:#333;\">${label}</span>
                    </span>`;
            } else if (flow.establishmentComplete) {
                closeTypeText = '• Still open';
            } else {
                closeTypeText = '• Incomplete';
            }

            const item = document.createElement('div');
            item.className = 'flow-item';
            item.dataset.flowId = String(flow.id);
            item.style.borderLeft = `4px solid ${color}`;

            // Build button HTML based on whether packet data is available
            const viewBtnHTML = hasPacketData
                ? `<button class=\"flow-view-btn\" data-flow-id=\"${flow.id}\" style=\"padding:2px 8px; font-size:10px; border:1px solid #2196F3; border-radius:3px; background:#2196F3; color:white; cursor:pointer; font-weight:bold;\" title=\"View packets with arcs\">📊 View Packets</button>`
                : `<button class=\"flow-view-btn\" data-flow-id=\"${flow.id}\" style=\"padding:2px 8px; font-size:10px; border:1px solid #ccc; border-radius:3px; background:#eee; color:#999; cursor:not-allowed; font-weight:bold;\" title=\"Packet data not available (summary mode)\" disabled>📊 View Packets</button>`;

            const exportBtnHTML = hasPacketData
                ? `<button class=\"flow-export-btn\" data-flow-id=\"${flow.id}\" style=\"margin-left:auto; padding:2px 6px; font-size:10px; border:1px solid #ced4da; border-radius:3px; background:#fff; cursor:pointer;\">Export CSV</button>`
                : `<button class=\"flow-export-btn\" data-flow-id=\"${flow.id}\" style=\"margin-left:auto; padding:2px 6px; font-size:10px; border:1px solid #ccc; border-radius:3px; background:#eee; color:#999; cursor:not-allowed;\" title=\"Packet data not available (summary mode)\" disabled>Export CSV</button>`;

            item.innerHTML = `
                <input type=\"checkbox\" class=\"flow-checkbox\" id=\"flow-${flow.id}\" ${selectedFlowIds.has(String(flow.id)) ? 'checked' : ''}>
                <div class=\"flow-info\">
                    <div class=\"flow-connection\">${flow.initiator}:${flow.initiatorPort} ↔ ${flow.responder}:${flow.responderPort}</div>
                    <div class=\"flow-details\">
                        <span class=\"flow-status ${flow.state}\">${String(flow.state || '').replace('_',' ')}</span>
                        <span>${flow.totalPackets} packets</span>
                        <span>${formatBytes(flow.totalBytes)}</span>
                        <span>${duration}s duration</span>
                        <span>${closeTypeText}</span>
                        <button class=\"flow-zoom-btn\" data-flow-id=\"${flow.id}\" title=\"Zoom timeline to this flow\">🔍 Zoom</button>
                        ${viewBtnHTML}
                        ${exportBtnHTML}
                    </div>
                    <div style=\"font-size:10px; color:#999; margin-top:3px;\">Start: ${startTime} • End: ${endTime}</div>
                </div>`;

            const cb = item.querySelector('.flow-checkbox');
            cb.addEventListener('change', (e) => {
                const flowId = String(flow.id);
                if (cb.checked) { selectedFlowIds.add(flowId); item.classList.add('selected'); }
                else { selectedFlowIds.delete(flowId); item.classList.remove('selected'); }
                if (typeof updateTcpFlowPacketsGlobal === 'function') updateTcpFlowPacketsGlobal();
            });
            item.addEventListener('click', (e) => {
                if (e.target && e.target.type !== 'checkbox') cb.click();
            });
            const zoomBtn = item.querySelector('.flow-zoom-btn');
            zoomBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                if (typeof zoomToFlow === 'function') zoomToFlow(flow);
            });
            const exportBtn = item.querySelector('.flow-export-btn');
            exportBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                if (typeof exportFlowToCSV === 'function') exportFlowToCSV(flow);
            });

            // View Packets button - enters flow detail mode
            const viewBtn = item.querySelector('.flow-view-btn');
            if (viewBtn) {
                viewBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    if (typeof enterFlowDetailMode === 'function') {
                        // Close the modal before entering flow detail mode
                        const modalOverlay = document.getElementById('flowListModalOverlay');
                        if (modalOverlay) modalOverlay.style.display = 'none';
                        enterFlowDetailMode(flow);
                    } else {
                        console.warn('Flow detail mode not available');
                    }
                });
            }

            if (selectedFlowIds.has(String(flow.id))) item.classList.add('selected');
            container.appendChild(item);
        }

        index = end;
        if (shouldShowProgress) {
            updateFlowProgress(end / currentPageFlows.length);
        }
        if (index < currentPageFlows.length) {
            requestAnimationFrame(renderBatch);
        } else if (shouldShowProgress) {
            hideFlowProgress();
        }
    }

    requestAnimationFrame(renderBatch);

    // If rendering in modal, update header count
    const countEl = document.getElementById('flowListModalCount');
    if (countEl) countEl.textContent = `${total.toLocaleString()} flow(s)`;
}

export function wireSidebarControls(opts) {
    const on = (id, type, handler) => { const el = document.getElementById(id); if (el && handler) el.addEventListener(type, handler); };
    on('ipSearch', 'input', (e) => { if (opts.onIpSearch) opts.onIpSearch(e.target.value); });
    on('selectAllIPs', 'click', () => { if (opts.onSelectAllIPs) opts.onSelectAllIPs(); });
    on('clearAllIPs', 'click', () => { if (opts.onClearAllIPs) opts.onClearAllIPs(); });

    on('showTcpFlows', 'change', (e) => { if (opts.onToggleShowTcpFlows) opts.onToggleShowTcpFlows(e.target.checked); });
    on('showEstablishment', 'change', (e) => { if (opts.onToggleEstablishment) opts.onToggleEstablishment(e.target.checked); });
    on('showDataTransfer', 'change', (e) => { if (opts.onToggleDataTransfer) opts.onToggleDataTransfer(e.target.checked); });
    on('showClosing', 'change', (e) => { if (opts.onToggleClosing) opts.onToggleClosing(e.target.checked); });
    on('showGroundTruth', 'change', (e) => { if (opts.onToggleGroundTruth) opts.onToggleGroundTruth(e.target.checked); });
    on('toggleBinning', 'change', (e) => { if (opts.onToggleBinning) opts.onToggleBinning(e.target.checked); });

    // Render mode radios
    const modeCircles = document.getElementById('renderModeCircles');
    const modeBars = document.getElementById('renderModeBars');
    if (modeCircles && modeBars && opts.onToggleRenderMode) {
        const handler = () => {
            const mode = modeBars.checked ? 'bars' : 'circles';
            opts.onToggleRenderMode(mode);
        };
        modeCircles.addEventListener('change', handler);
        modeBars.addEventListener('change', handler);
    }
}

export function updateFlagStats(packets, classifyFlags, flagColors) {
    const container = document.getElementById('flagStats');
    if (!container) return;
    if (!packets || packets.length === 0) {
        container.innerHTML = '<div style="color: #666;">No data to display</div>';
        return;
    }
    const flagCounts = {};
    packets.forEach(packet => {
        const ft = classifyFlags(packet.flags);
        flagCounts[ft] = (flagCounts[ft] || 0) + 1;
    });
    const sortedFlags = Object.entries(flagCounts).sort(([,a],[,b]) => b - a);
    let html = '';
    sortedFlags.forEach(([flag, count]) => {
        const color = flagColors[flag] || '#95a5a6';
        const hasDefinedColor = Object.prototype.hasOwnProperty.call(flagColors, flag);
        html += `
            <div style="display:flex; align-items:center; margin-bottom:3px; cursor:pointer;" data-flag="${flag}">
                <div style="width:12px; height:12px; background-color:${color}; margin-right:8px; border-radius:2px; ${hasDefinedColor ? '' : 'border:1px solid #666;'}"></div>
                <span>${flag}: ${count.toLocaleString()}</span>
                ${hasDefinedColor ? '' : '<span style="color:#666; font-size:10px; margin-left:5px;">(no color)</span>'}
            </div>`;
    });
    container.innerHTML = html || '<div style="color:#666;">No TCP packets found</div>';
}

export function updateIPStats(packets, flagColors, formatBytes) {
    const container = document.getElementById('ipStats');
    if (!container) return;
    if (!packets || packets.length === 0) {
        container.innerHTML = '<div style="color: #666;">Select IPs to view statistics</div>';
        return;
    }
    const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')).map(cb => cb.value);
    if (selectedIPs.length === 0) {
        container.innerHTML = '<div style="color: #666;">Select IPs to view statistics</div>';
        return;
    }
    const ipStats = {};
    selectedIPs.forEach(ip => {
        ipStats[ip] = { sent:0, received:0, total:0, bytes_sent:0, bytes_received:0, total_bytes:0, connections:new Set(), flags_sent:{}, flags_received:{} };
        Object.keys(flagColors).forEach(flag => { ipStats[ip].flags_sent[flag]=0; ipStats[ip].flags_received[flag]=0; });
    });
    packets.forEach(p => {
        const flagType = p.flag_type || p.flags;
        const fStr = typeof flagType === 'string' ? flagType : (p.flag_type || '');
        const size = p.length || 0;
        if (ipStats[p.src_ip]) { const s=ipStats[p.src_ip]; s.sent++; s.total++; s.bytes_sent+=size; s.total_bytes+=size; s.connections.add(p.dst_ip); if (s.flags_sent[fStr]!==undefined) s.flags_sent[fStr]++; }
        if (ipStats[p.dst_ip]) { const s=ipStats[p.dst_ip]; s.received++; s.total++; s.bytes_received+=size; s.total_bytes+=size; s.connections.add(p.src_ip); if (s.flags_received[fStr]!==undefined) s.flags_received[fStr]++; }
    });
    const flagsToHtml = (m) => {
        const arr = Object.entries(m).filter(([,c])=>c>0).sort(([,a],[,b])=>b-a);
        if (!arr.length) return '<span style="color:#999; font-style:italic;">None</span>';
        return arr.map(([flag,count])=>`<span style="display:inline-flex; align-items:center; gap:4px; padding:2px 4px; border:1px solid #e9ecef; border-radius:3px; background:#fff;"><span style="width:10px; height:10px; background:${flagColors[flag]||'#bdc3c7'}; border-radius:2px;"></span><span style="font-size:10px; color:#555;">${flag} (${count})</span></span>`).join(' ');
    };
    let html = '<div style="font-weight:bold; margin-bottom:10px; border-bottom:1px solid #eee; padding-bottom:5px;">Selected IP Statistics</div>';
    selectedIPs.forEach(ip=>{
        const s = ipStats[ip];
        const connectionCount = s.connections.size;
        html += `
          <div style="margin-bottom:15px; padding:8px; border:1px solid #e9ecef; border-radius:3px;">
            <div style="font-weight:bold; color:#495057; margin-bottom:8px;">${ip}</div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:5px; font-size:11px; margin-bottom:8px;">
              <div>Sent: ${s.sent.toLocaleString()}</div>
              <div>Received: ${s.received.toLocaleString()}</div>
              <div>Total: ${s.total.toLocaleString()}</div>
              <div>Connections: ${connectionCount}</div>
              <div>Bytes Sent: ${formatBytes(s.bytes_sent)}</div>
              <div>Bytes Recv: ${formatBytes(s.bytes_received)}</div>
            </div>
            <div style="margin-bottom:5px;"><div style="font-size:10px; color:#666; margin-bottom:3px;">Flags Sent:</div><div style="display:flex; flex-wrap:wrap; gap:3px;">${flagsToHtml(s.flags_sent)}</div></div>
            <div><div style="font-size:10px; color:#666; margin-bottom:3px;">Flags Received:</div><div style="display:flex; flex-wrap:wrap; gap:3px;">${flagsToHtml(s.flags_received)}</div></div>
          </div>`;
    });
    container.innerHTML = html;
}

export function createFlowList(flows, selectedFlowIds, formatBytes, formatTimestamp, exportFlowToCSV, zoomToFlow, updateTcpFlowPacketsGlobal, flowColors = {}) {
    const container = document.getElementById('flowListModalList') || document.getElementById('flowList');
    if (!container) return;
    if (!flows || flows.length === 0) {
        container.innerHTML = '<div style="color:#666; text-align:center; padding:20px;">No flows to display</div>';
        return;
    }
    const sorted = [...flows].sort((a,b)=>a.startTime - b.startTime);

    // Use flow legend helpers from legends.js
    const closeColors = getFlowColors(flowColors);
    const invalidLabels = getInvalidLabels();
    let html = '';
    sorted.forEach(flow => {
        const duration = Math.round((flow.endTime - flow.startTime) / 1000000);
        const { utcTime: startTime } = formatTimestamp(flow.startTime);
        const { utcTime: endTime } = formatTimestamp(flow.endTime);
        const reason = getInvalidReason(flow);
        const color = getFlowColor(flow, flowColors);
        let closeTypeText = '';
        if (reason) {
            const label = invalidLabels[reason] || 'Invalid';
            closeTypeText = `
                <span style="display:inline-flex; align-items:center; gap:6px;">
                    <span style="display:inline-block; width:10px; height:10px; border-radius:2px; background:${color}; border:1px solid #fff; box-shadow:0 0 0 1px rgba(0,0,0,0.08);"></span>
                    <span style="color:#333;">${label}</span>
                </span>`;
        } else if (flow.closeType === 'graceful' || flow.closeType === 'abortive') {
            const label = flow.closeType === 'graceful' ? 'Graceful close' : 'Abortive close';
            closeTypeText = `
                <span style="display:inline-flex; align-items:center; gap:6px;">
                    <span style="display:inline-block; width:10px; height:10px; border-radius:2px; background:${color}; border:1px solid #fff; box-shadow:0 0 0 1px rgba(0,0,0,0.08);"></span>
                    <span style="color:#333;">${label}</span>
                </span>`;
        } else if (flow.establishmentComplete) {
            closeTypeText = '• Still open';
        } else {
            closeTypeText = '• Incomplete';
        }
        html += `
          <div class="flow-item" data-flow-id="${flow.id}" style="border-left: 4px solid ${color};">
            <input type="checkbox" class="flow-checkbox" id="flow-${flow.id}" ${selectedFlowIds.has(String(flow.id)) ? 'checked' : ''}>
            <div class="flow-info">
              <div class="flow-connection">${flow.initiator}:${flow.initiatorPort} ↔ ${flow.responder}:${flow.responderPort}</div>
              <div class="flow-details">
                <span class="flow-status ${flow.state}">${flow.state.replace('_',' ')}</span>
                <span>${flow.totalPackets} packets</span>
                <span>${formatBytes(flow.totalBytes)}</span>
                <span>${duration}s duration</span>
                <span>${closeTypeText}</span>
                <button class="flow-zoom-btn" data-flow-id="${flow.id}" title="Zoom timeline to this flow">🔍 Zoom</button>
                <button class="flow-export-btn" data-flow-id="${flow.id}" style="margin-left:auto; padding:2px 6px; font-size:10px; border:1px solid #ced4da; border-radius:3px; background:#fff; cursor:pointer;">Export CSV</button>
              </div>
              <div style="font-size:10px; color:#999; margin-top:3px;">Start: ${startTime} • End: ${endTime}</div>
            </div>
          </div>`;
    });
    container.innerHTML = html;
    container.querySelectorAll('.flow-export-btn').forEach(btn => btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const flowId = e.currentTarget.dataset.flowId;
        const f = flows.find(x => String(x.id) === String(flowId));
        if (f) exportFlowToCSV(f);
    }));
    container.querySelectorAll('.flow-zoom-btn').forEach(btn => btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const flowId = e.currentTarget.dataset.flowId;
        const f = flows.find(x => String(x.id) === String(flowId));
        if (f) zoomToFlow(f);
    }));
    container.querySelectorAll('.flow-checkbox').forEach(cb => cb.addEventListener('change', (e) => {
        const flowId = e.target.id.replace('flow-','');
        const flowItem = e.target.closest('.flow-item');
        if (e.target.checked) { selectedFlowIds.add(flowId); flowItem.classList.add('selected'); }
        else { selectedFlowIds.delete(flowId); flowItem.classList.remove('selected'); }
        if (typeof updateTcpFlowPacketsGlobal === 'function') updateTcpFlowPacketsGlobal();
    }));
    container.querySelectorAll('.flow-item').forEach(item => item.addEventListener('click', (e) => {
        if (e.target && e.target.type !== 'checkbox') {
            const cb = item.querySelector('.flow-checkbox');
            if (cb) cb.click();
        }
    }));
    selectedFlowIds.forEach(id => { const el = container.querySelector(`[data-flow-id="${id}"]`); if (el) el.classList.add('selected'); });

    // If rendering in modal, update header count
    const countEl = document.getElementById('flowListModalCount');
    if (countEl) countEl.textContent = `${flows.length.toLocaleString()} flow(s)`;
}

// Modal helpers for the Flow List popup
export function showFlowListModal() {
    const overlay = document.getElementById('flowListModalOverlay');
    if (!overlay) return;
    overlay.style.display = 'flex';
    // Center modal on first open or keep previous position if moved
    try {
        const modal = document.getElementById('flowListModal');
        if (!modal) return;
        const hasPosition = modal.dataset.positioned === 'true';
        if (!hasPosition) {
            // Center within viewport
            const vw = window.innerWidth, vh = window.innerHeight;
            const rect = modal.getBoundingClientRect();
            const left = Math.max(8, (vw - rect.width) / 2);
            const top = Math.max(8, (vh - rect.height) / 2);
            modal.style.left = `${left}px`;
            modal.style.top = `${top}px`;
            modal.dataset.positioned = 'true';
        }
    } catch (_) {}
}

export function hideFlowListModal() {
    const overlay = document.getElementById('flowListModalOverlay');
    if (overlay) overlay.style.display = 'none';
}

let flowListModalWired = false;
export function wireFlowListModalControls({ onSelectAll, onClearAll, onSearch } = {}) {
    if (flowListModalWired) return;
    flowListModalWired = true;
    const overlay = document.getElementById('flowListModalOverlay');
    const closeBtn = document.getElementById('flowListModalClose');
    const selectAllBtn = document.getElementById('flowListModalSelectAll');
    const clearAllBtn = document.getElementById('flowListModalClearAll');
    const searchInput = document.getElementById('flowListModalSearch');
    const modal = document.getElementById('flowListModal');
    const header = modal ? modal.querySelector('.modal-header') : null;

    // Overlay is non-blocking and click-through; close via button only
    if (closeBtn) closeBtn.addEventListener('click', hideFlowListModal);
    if (selectAllBtn && typeof onSelectAll === 'function') selectAllBtn.addEventListener('click', onSelectAll);
    if (clearAllBtn && typeof onClearAll === 'function') clearAllBtn.addEventListener('click', onClearAll);
    if (searchInput && typeof onSearch === 'function') searchInput.addEventListener('input', (e) => onSearch(e.target.value));

    // Draggable modal via header
    if (modal && header) {
        let isDragging = false;
        let startX = 0, startY = 0, origLeft = 0, origTop = 0;
        const onMouseMove = (e) => {
            if (!isDragging) return;
            const dx = e.clientX - startX;
            const dy = e.clientY - startY;
            const newLeft = Math.max(8, Math.min(window.innerWidth - modal.offsetWidth - 8, origLeft + dx));
            const newTop = Math.max(8, Math.min(window.innerHeight - modal.offsetHeight - 8, origTop + dy));
            modal.style.left = `${newLeft}px`;
            modal.style.top = `${newTop}px`;
            modal.dataset.positioned = 'true';
        };
        const onMouseUp = () => {
            if (!isDragging) return;
            isDragging = false;
            document.removeEventListener('mousemove', onMouseMove);
            document.removeEventListener('mouseup', onMouseUp);
        };
        header.addEventListener('mousedown', (e) => {
            // Only start dragging with primary button
            if (e.button !== 0) return;
            isDragging = true;
            startX = e.clientX;
            startY = e.clientY;
            const rect = modal.getBoundingClientRect();
            origLeft = rect.left;
            origTop = rect.top;
            document.addEventListener('mousemove', onMouseMove);
            document.addEventListener('mouseup', onMouseUp);
        });
    }
}

export function updateTcpFlowStats(flows, selectedFlowIds, formatBytes) {
    const container = document.getElementById('tcpFlowStats');
    if (!container) return;
    if (!flows || flows.length === 0) {
        container.innerHTML = 'Select 2 or more IP addresses to view TCP flow statistics';
        container.style.color = '#666';
        return;
    }
    const totalStats = {
        total: flows.length,
        established: flows.filter(f => f.establishmentComplete === true || f.state === 'established' || f.state === 'closed').length,
        withData: flows.filter(f => f.dataTransferStarted === true).length,
        gracefulClose: flows.filter(f => f.closeType === 'graceful').length,
        abortiveClose: flows.filter(f => f.closeType === 'abortive').length,
        invalid: flows.filter(f => f.closeType === 'invalid' || f.state === 'invalid').length,
        totalPackets: flows.reduce((sum, f) => sum + (parseInt(f.totalPackets) || 0), 0),
        totalBytes: flows.reduce((sum, f) => sum + (parseInt(f.totalBytes) || 0), 0)
    };
    const selectedFlows = flows.filter(f => selectedFlowIds.has(String(f.id)));
    const selectedStats = {
        selected: selectedFlows.length,
        established: selectedFlows.filter(f => f.establishmentComplete === true || f.state === 'established' || f.state === 'closed').length,
        withData: selectedFlows.filter(f => f.dataTransferStarted === true).length,
        gracefulClose: selectedFlows.filter(f => f.closeType === 'graceful').length,
        abortiveClose: selectedFlows.filter(f => f.closeType === 'abortive').length,
        invalid: selectedFlows.filter(f => f.closeType === 'invalid' || f.state === 'invalid').length,
        totalPackets: selectedFlows.reduce((sum, f) => sum + (parseInt(f.totalPackets) || 0), 0),
        totalBytes: selectedFlows.reduce((sum, f) => sum + (parseInt(f.totalBytes) || 0), 0)
    };
    let statsHTML = `<strong>${totalStats.total} TCP flow(s) for selected IPs (${selectedStats.selected} checked)</strong><br>`;
    if (totalStats.total > 0) {
        statsHTML += `<div style="margin-top:8px;">`;
        statsHTML += `• Fully established: ${totalStats.established}<br>`;
        statsHTML += `• With data transfer: ${totalStats.withData}<br>`;
        statsHTML += `• Graceful close: ${totalStats.gracefulClose}<br>`;
        statsHTML += `• Abortive close: ${totalStats.abortiveClose}<br>`;
        if (totalStats.invalid > 0) statsHTML += `• <span style="color:#e74c3c;">Invalid connections: ${totalStats.invalid}</span><br>`;
        statsHTML += `• Total packets: ${totalStats.totalPackets.toLocaleString()}<br>`;
        statsHTML += `• Total bytes: ${formatBytes(totalStats.totalBytes)}`;
        statsHTML += `</div>`;
        if (selectedStats.selected > 0) {
            statsHTML += `<div style=\"margin-top:8px; padding-top:8px; border-top:1px solid #eee; color:#007bff;\">`;
            statsHTML += `<strong>Checked flows (${selectedStats.selected}):</strong><br>`;
            statsHTML += `• Packets: ${selectedStats.totalPackets.toLocaleString()}, Bytes: ${formatBytes(selectedStats.totalBytes)}`;
            statsHTML += `</div>`;
        }
    } else {
        statsHTML += `<div style="color:#999; font-style:italic; margin-top:5px;">No flows match selected IP addresses</div>`;
    }
    container.innerHTML = statsHTML;
    container.style.color = '#27ae60';
}

export function updateGroundTruthStatsUI(html, ok=true) {
    const container = document.getElementById('groundTruthStats');
    if (!container) return;
    container.innerHTML = html;
    container.style.color = ok ? '#27ae60' : '#e74c3c';
}
