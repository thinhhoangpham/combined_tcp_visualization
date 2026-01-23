// Overview chart module: manages stacked invalid flows overview, brush, and legends
import { GLOBAL_BIN_COUNT } from './config.js';
import { createOverviewFlowLegend } from './legends.js';
import { showFlowListModal } from './sidebar.js';
// Internal state
let overviewSvg, overviewXScale, overviewBrush, overviewWidth = 0, overviewHeight = 100;
let isUpdatingFromBrush = false; // prevent circular updates
let isUpdatingFromZoom = false;  // prevent circular updates

// External references provided via init
let d3Ref = null;
let applyZoomDomainRef = null;
let getWidthRef = null;
let getTimeExtentRef = null;
let getCurrentDomainRef = null; // Get current zoom domain from main chart
let getOverviewTimeExtentRef = null; // Get overview time extent (TimeArcs range or full data)
let getChartMarginsRef = null;
let getCurrentFlowsRef = null;
let getSelectedFlowIdsRef = null;
let updateTcpFlowPacketsGlobalRef = null;
let sbRenderInvalidLegendRef = null;
let sbRenderClosingLegendRef = null;
let makeConnectionKeyRef = null;
let hiddenInvalidReasonsRef = null;
let hiddenCloseTypesRef = null;
let applyInvalidReasonFilterRef = null; // callback from main to hide/show dots/arcs
let createFlowListRef = null; // callback to populate flow list
let loadPacketBinRef = null; // optional: load packets for a given bin index
let loadChunksForTimeRangeRef = null; // async: load flows for a time range from chunked data
let getIpPairOverviewRef = null; // Get precomputed IP pair overview data
let getSelectedIPsRef = null; // Get currently selected IP addresses

// Config shared with main (imported)
let flagColors = {};
let flowColors = {};

export function initOverview(options) {
    d3Ref = options.d3;
    applyZoomDomainRef = options.applyZoomDomain;
    getWidthRef = options.getWidth;
    getChartMarginsRef = options.getChartMargins || (() => ({ left: 150, right: 120, top: 80, bottom: 50 }));
    getTimeExtentRef = options.getTimeExtent;
    getCurrentDomainRef = options.getCurrentDomain; // Get current zoom domain
    getOverviewTimeExtentRef = options.getOverviewTimeExtent; // Get overview extent (TimeArcs or full)
    getCurrentFlowsRef = options.getCurrentFlows;
    getSelectedFlowIdsRef = options.getSelectedFlowIds;
    updateTcpFlowPacketsGlobalRef = options.updateTcpFlowPacketsGlobal;
    sbRenderInvalidLegendRef = options.sbRenderInvalidLegend;
    sbRenderClosingLegendRef = options.sbRenderClosingLegend;
    makeConnectionKeyRef = options.makeConnectionKey;
    hiddenInvalidReasonsRef = options.hiddenInvalidReasons;
    hiddenCloseTypesRef = options.hiddenCloseTypes;
    applyInvalidReasonFilterRef = options.applyInvalidReasonFilter;
    createFlowListRef = options.createFlowList;
    loadPacketBinRef = options.loadPacketBin;
    loadChunksForTimeRangeRef = options.loadChunksForTimeRange;
    // Bin count is centralized in config.js; ignore per-call overrides
    flagColors = options.flagColors || {};
    flowColors = options.flowColors || {};
}

export function createOverviewChart(packets, { timeExtent, width, margins }) {
    console.log(`[OverviewChart] createOverviewChart called, timeExtent:`, timeExtent);
    const d3 = d3Ref;
    if (!d3) {
        console.error('[OverviewChart] d3Ref is not set! initOverview may not have been called.');
        return;
    }
    d3.select('#overview-chart').html('');
    const container = document.getElementById('overview-container');
    if (container) container.style.display = 'block';

    // Align overview with main chart: use identical inner width and left/right margins
    const chartMargins = margins || (getChartMarginsRef ? getChartMarginsRef() : { left: 150, right: 120, top: 80, bottom: 50 });
    const legendHeight = 35; // Space for horizontal legend
    const overviewMargin = { top: 15 + legendHeight, right: chartMargins.right, bottom: 30, left: chartMargins.left };
    overviewWidth = Math.max(100, width);
    overviewHeight = 100;

    const overviewSvgContainer = d3.select('#overview-chart').append('svg')
        .attr('width', overviewWidth + overviewMargin.left + overviewMargin.right)
        .attr('height', overviewHeight + overviewMargin.top + overviewMargin.bottom);

    overviewSvg = overviewSvgContainer.append('g')
        .attr('transform', `translate(${overviewMargin.left},${overviewMargin.top})`);

    overviewXScale = d3.scaleLinear().domain(timeExtent).range([0, overviewWidth]);

    const binCount = (typeof GLOBAL_BIN_COUNT === 'number')
        ? GLOBAL_BIN_COUNT
        : (GLOBAL_BIN_COUNT.OVERVIEW || GLOBAL_BIN_COUNT.ARCS || GLOBAL_BIN_COUNT.BAR || 300);
    const totalRange = Math.max(1, (timeExtent[1] - timeExtent[0]));
    const timeBinSize = totalRange / binCount;

    // Get flows and filter to only those within the time extent
    // This ensures legend counts match what's displayed in the chart
    console.log(`[OverviewChart] getCurrentFlowsRef defined: ${!!getCurrentFlowsRef}, returns:`, getCurrentFlowsRef ? getCurrentFlowsRef() : 'N/A');
    const rawFlows = Array.isArray(getCurrentFlowsRef ? getCurrentFlowsRef() : null) ? getCurrentFlowsRef() : [];
    console.log(`[OverviewChart] rawFlows.length: ${rawFlows.length}`);

    // Debug: log time extent and flow startTime range (use loop to avoid stack overflow)
    if (rawFlows.length > 0) {
        let flowMin = Infinity, flowMax = -Infinity, withinCount = 0;
        for (const f of rawFlows) {
            if (f && typeof f.startTime === 'number') {
                if (f.startTime < flowMin) flowMin = f.startTime;
                if (f.startTime > flowMax) flowMax = f.startTime;
                if (f.startTime >= timeExtent[0] && f.startTime < timeExtent[1]) withinCount++;
            }
        }
        console.log(`[OverviewChart] timeExtent: [${timeExtent[0]}, ${timeExtent[1]}]`);
        console.log(`[OverviewChart] rawFlows count: ${rawFlows.length}, startTime range: [${flowMin}, ${flowMax}]`);
        console.log(`[OverviewChart] flows within timeExtent: ${withinCount}`);
    }

    const allFlows = rawFlows.filter(f =>
        f && typeof f.startTime === 'number' &&
        f.startTime >= timeExtent[0] && f.startTime < timeExtent[1]
    );
    // Separate invalid-like flows for the bottom histogram
    const invalidFlows = allFlows.filter(f => f && (f.closeType === 'invalid' || f.state === 'invalid' || f.invalidReason));
    // Separate closing types for the top histogram
    const closingTypes = ['graceful', 'abortive'];
    const closingFlows = allFlows.filter(f => f && closingTypes.includes(f.closeType));
    // Separate ongoing types (middle histogram band)
    const isInvalid = (f) => f && (f.closeType === 'invalid' || f.state === 'invalid' || !!f.invalidReason);
    const isClosedGraceful = (f) => f && f.closeType === 'graceful';
    const isClosedAbortive = (f) => f && f.closeType === 'abortive';
    const isClosed = (f) => isClosedGraceful(f) || isClosedAbortive(f);
    const isOngoingCandidate = (f) => f && !isInvalid(f) && !isClosed(f);
    const isOpen = (f) => isOngoingCandidate(f) && (f.establishmentComplete === true || f.state === 'established' || f.state === 'data_transfer');
    const isIncomplete = (f) => isOngoingCandidate(f) && !isOpen(f);
    const ongoingTypes = ['open', 'incomplete'];
    const ongoingClassifier = (f) => isOpen(f) ? 'open' : (isIncomplete(f) ? 'incomplete' : null);

    const invalidLabels = {
        'invalid_ack': 'Invalid ACK',
        'rst_during_handshake': 'RST during handshake',
        'incomplete_no_synack': 'Incomplete (no SYN+ACK)',
        'incomplete_no_ack': 'Incomplete (no ACK)',
        'invalid_synack': 'Invalid SYN+ACK',
        'unknown_invalid': 'Invalid (unspecified)'
    };
    const invalidDescriptions = {
        'invalid_ack': 'SYN and SYN+ACK observed but the final ACK from the client was missing, malformed, or out of order. The 3-way handshake did not complete cleanly.',
        'rst_during_handshake': 'A connection reset (RST) occurred during the TCP 3-way handshake before the session was established.',
        'incomplete_no_synack': 'A SYN was sent but no SYN+ACK response was observed. The server did not reply or the packet was not captured.',
        'incomplete_no_ack': 'SYN and SYN+ACK were seen, but the final ACK from the client was not observed to complete the handshake.',
        'invalid_synack': 'The SYN+ACK response was invalid (e.g., unexpected seq/ack numbers or incorrect flag combination).',
        'unknown_invalid': 'The flow was marked invalid, but no specific root cause was classified.'
    };
    // Build invalid reason colors, prefer explicit flowColors.invalid overrides
    const invalidFlowColors = {
        'invalid_ack': (flowColors.invalid && flowColors.invalid['invalid_ack']) || d3.color(flagColors['ACK'] || '#27ae60').darker(0.5).formatHex(),
        'invalid_synack': (flowColors.invalid && flowColors.invalid['invalid_synack']) || d3.color(flagColors['SYN+ACK'] || '#f39c12').darker(0.5).formatHex(),
        'rst_during_handshake': (flowColors.invalid && flowColors.invalid['rst_during_handshake']) || d3.color(flagColors['RST'] || '#34495e').darker(0.5).formatHex(),
        'incomplete_no_synack': (flowColors.invalid && flowColors.invalid['incomplete_no_synack']) || d3.color(flagColors['SYN+ACK'] || '#f39c12').brighter(0.5).formatHex(),
        'incomplete_no_ack': (flowColors.invalid && flowColors.invalid['incomplete_no_ack']) || d3.color(flagColors['ACK'] || '#27ae60').brighter(0.5).formatHex(),
        'unknown_invalid': (flowColors.invalid && flowColors.invalid['unknown_invalid']) || d3.color(flagColors['OTHER'] || '#bdc3c7').darker(0.5).formatHex()
    };
    const invalidOrder = [
        'invalid_ack',
        'rst_during_handshake',
        'incomplete_no_synack',
        'incomplete_no_ack',
        'invalid_synack',
        'unknown_invalid'
    ];
    const getInvalidReason = (f) => {
        if (!f) return null;
        const r = f.invalidReason;
        if (r && invalidOrder.includes(r)) return r;
        if (f.closeType === 'invalid' || f.state === 'invalid') return 'unknown_invalid';
        return null;
    };

    const axisY = overviewHeight - 30;

    const presentReasonsSet = new Set();
    for (const f of invalidFlows) {
        if (f && (typeof f.startTime === 'number')) {
            const r = getInvalidReason(f);
            if (r) presentReasonsSet.add(r);
        }
    }
    const presentReasons = invalidOrder.filter(r => presentReasonsSet.has(r));
    const reasons = presentReasons.length ? presentReasons : ['unknown_invalid'];

    const rows = Math.max(1, reasons.length);
    const rowsHeight = Math.max(20, axisY - 6);
    const rowHeight = rowsHeight / rows;
    const reasonY = new Map(reasons.map((r, i) => [r, (i + 0.5) * rowHeight]));

    // Build binned maps for invalid reasons (bottom) and closing types (top)
    // Note: flows outside the timeExtent are EXCLUDED, not clamped to edge bins
    const binReasonMap = new Map();
    for (const f of invalidFlows) {
        if (!f || typeof f.startTime !== 'number') continue;
        // Skip flows outside the time extent
        if (f.startTime < timeExtent[0] || f.startTime >= timeExtent[1]) continue;
        const reason = getInvalidReason(f);
        if (!reason) continue;
        const idx = Math.floor((f.startTime - timeExtent[0]) / timeBinSize);
        let m = binReasonMap.get(idx);
        if (!m) { m = new Map(); binReasonMap.set(idx, m); }
        const arr = m.get(reason) || [];
        arr.push(f);
        m.set(reason, arr);
    }
    // Build bins for closing types (top histogram)
    const binCloseMap = new Map();
    for (const f of closingFlows) {
        if (!f || typeof f.startTime !== 'number') continue;
        // Skip flows outside the time extent
        if (f.startTime < timeExtent[0] || f.startTime >= timeExtent[1]) continue;
        const t = f.closeType;
        if (!closingTypes.includes(t)) continue;
        const idx = Math.floor((f.startTime - timeExtent[0]) / timeBinSize);
        let m = binCloseMap.get(idx);
        if (!m) { m = new Map(); binCloseMap.set(idx, m); }
        const arr = m.get(t) || [];
        arr.push(f);
        m.set(t, arr);
    }
    // Build bins for ongoing types (middle histogram)
    const binOngoingMap = new Map();
    for (const f of allFlows) {
        if (!f || typeof f.startTime !== 'number') continue;
        // Skip flows outside the time extent
        if (f.startTime < timeExtent[0] || f.startTime >= timeExtent[1]) continue;
        if (isInvalid(f) || isClosed(f)) continue;
        const t = ongoingClassifier(f);
        if (!t) continue;
        const idx = Math.floor((f.startTime - timeExtent[0]) / timeBinSize);
        let m = binOngoingMap.get(idx);
        if (!m) { m = new Map(); binOngoingMap.set(idx, m); }
        const arr = m.get(t) || [];
        arr.push(f);
        m.set(t, arr);
    }

    // Compute per-bin totals and global max per direction
    let maxBinTotalInvalid = 0;
    const binTotalsInvalid = new Map();
    for (let i = 0; i < binCount; i++) {
        const m = binReasonMap.get(i);
        let total = 0;
        if (m) for (const arr of m.values()) total += arr.length;
        binTotalsInvalid.set(i, total);
        if (total > maxBinTotalInvalid) maxBinTotalInvalid = total;
    }
    maxBinTotalInvalid = Math.max(1, maxBinTotalInvalid);

    let maxBinTotalClosing = 0;
    const binTotalsClosing = new Map();
    for (let i = 0; i < binCount; i++) {
        const m = binCloseMap.get(i);
        let total = 0;
        if (m) for (const arr of m.values()) total += arr.length;
        binTotalsClosing.set(i, total);
        if (total > maxBinTotalClosing) maxBinTotalClosing = total;
    }
    maxBinTotalClosing = Math.max(1, maxBinTotalClosing);
    let maxBinTotalOngoing = 0;
    const binTotalsOngoing = new Map();
    for (let i = 0; i < binCount; i++) {
        const m = binOngoingMap.get(i);
        let total = 0;
        if (m) for (const arr of m.values()) total += arr.length;
        binTotalsOngoing.set(i, total);
        if (total > maxBinTotalOngoing) maxBinTotalOngoing = total;
    }
    maxBinTotalOngoing = Math.max(1, maxBinTotalOngoing);
    // Shared max across all bands so bar heights use the same scale
    const sharedMax = Math.max(1, maxBinTotalClosing, maxBinTotalOngoing, maxBinTotalInvalid);

    // Layout heights
    const chartHeightUp = Math.max(10, axisY - 6);
    // Split the upward area into two bands: closing (top) and ongoing (middle)
    const chartHeightUpOngoing = chartHeightUp * 0.45; // lower band (closest to axis)
    const chartHeightUpClosing = chartHeightUp - chartHeightUpOngoing; // remaining top band
    const brushTopY = overviewHeight - 4; // top of brush selection area
    // Push invalid bars down without reducing their total height
    const invalidAxisGap = 6; // pixels of vertical offset below the axis
    const chartHeightDown = Math.max(6, brushTopY - axisY - 4); // full available height

    // Colors for closing types (top)
    const closeColors = {
        graceful: (flowColors.closing && flowColors.closing.graceful) || '#8e44ad',
        abortive: (flowColors.closing && flowColors.closing.abortive) || '#c0392b'
    };
    const ongoingColors = {
        open: (flowColors.ongoing && flowColors.ongoing.open) || '#6c757d',
        incomplete: (flowColors.ongoing && flowColors.ongoing.incomplete) || '#adb5bd'
    };

    // Prepare render data for both directions
    const segments = [];
    for (let i = 0; i < binCount; i++) {
        const binStartTime = timeExtent[0] + i * timeBinSize;
        const binEndTime = binStartTime + timeBinSize;
        const x0 = overviewXScale(binStartTime);
        const x1 = overviewXScale(binEndTime);
        const widthPx = Math.max(1, x1 - x0);
        const baseX = x0;

        // Upward stacking: closing types (top band)
        let yTop = axisY - chartHeightUpOngoing;
        const mTop = binCloseMap.get(i) || new Map();
        const totalTop = binTotalsClosing.get(i) || 0;
        if (totalTop > 0) {
            for (const t of closingTypes) {
                const arr = mTop.get(t) || [];
                const count = arr.length;
                if (count === 0) continue;
                const h = (count / sharedMax) * chartHeightUpClosing;
                yTop -= h;
                segments.push({
                    kind: 'closing', closeType: t, reason: null,
                    x: baseX, y: yTop, width: widthPx, height: h,
                    count, flows: arr, binIndex: i
                });
            }
        }

        // Ongoing types (middle band) grow from band center
        const mMid = binOngoingMap.get(i) || new Map();
        const totalMid = binTotalsOngoing.get(i) || 0;
        if (totalMid > 0) {
            const centerY = axisY - (chartHeightUpOngoing / 2);
            // open: grow upward from center
            {
                const arr = mMid.get('open') || [];
                const count = arr.length;
                if (count > 0) {
                    const h = (count / sharedMax) * (chartHeightUpOngoing / 2);
                    const y = centerY - h;
                    segments.push({
                        kind: 'ongoing', closeType: 'open', reason: null,
                        x: baseX, y, width: widthPx, height: h,
                        count, flows: arr, binIndex: i
                    });
                }
            }
            // incomplete: grow downward from center
            {
                const arr = mMid.get('incomplete') || [];
                const count = arr.length;
                if (count > 0) {
                    const h = (count / sharedMax) * (chartHeightUpOngoing / 2);
                    const y = centerY;
                    segments.push({
                        kind: 'ongoing', closeType: 'incomplete', reason: null,
                        x: baseX, y, width: widthPx, height: h,
                        count, flows: arr, binIndex: i
                    });
                }
            }
        }

        // Downward stacking: invalid reasons
        let yBottom = axisY + invalidAxisGap;
        const mBot = binReasonMap.get(i) || new Map();
        const totalBot = binTotalsInvalid.get(i) || 0;
        if (totalBot > 0) {
            for (const reason of reasons) {
                const arr = mBot.get(reason) || [];
                const count = arr.length;
                if (count === 0) continue;
                const h = (count / sharedMax) * chartHeightDown;
                const y = yBottom; // start at baseline and grow downward
                yBottom += h;
                segments.push({
                    kind: 'invalid', reason, closeType: null,
                    x: baseX, y, width: widthPx, height: h,
                    count, flows: arr, binIndex: i
                });
            }
        }
    }

    // Amplify/reset functions per band to avoid vertical jumps
    const amplifyBinBand = (binIndex, bandKind) => {
        const targetSy = 1.8; // default magnification
        const axisY = overviewHeight - 30;

        const upTotalClose = (binTotalsClosing && binTotalsClosing.get) ? (binTotalsClosing.get(binIndex) || 0) : 0;
        const upTotalOngoing = (binTotalsOngoing && binTotalsOngoing.get) ? (binTotalsOngoing.get(binIndex) || 0) : 0;
        const downTotal = (binTotalsInvalid && binTotalsInvalid.get) ? (binTotalsInvalid.get(binIndex) || 0) : 0;
        const upHeightClose = (upTotalClose / Math.max(1, sharedMax)) * chartHeightUpClosing;
        const upHeightOngoing = (upTotalOngoing / Math.max(1, sharedMax)) * chartHeightUpOngoing;
        const downHeight = (downTotal / Math.max(1, sharedMax)) * chartHeightDown;

        // Allow extra magnification for very small bands so thin bars are visible
        const smallBandBoost = (hPx, baseCap) => {
            if (hPx <= 0.75) return Math.max(baseCap, 6.0);
            if (hPx <= 1.5) return Math.max(baseCap, 4.0);
            if (hPx <= 2.5) return Math.max(baseCap, 3.0);
            return baseCap;
        };

        // Per-band scale and pivot
        const syClose = Math.max(
            1.0,
            upHeightClose > 0
                ? Math.min(
                    smallBandBoost(upHeightClose, targetSy),
                    chartHeightUpClosing / Math.max(1e-6, upHeightClose)
                  )
                : 1.0
        );
        const syOngoing = Math.max(
            1.0,
            upHeightOngoing > 0
                ? Math.min(
                    smallBandBoost(upHeightOngoing, targetSy),
                    chartHeightUpOngoing / Math.max(1e-6, upHeightOngoing)
                  )
                : 1.0
        );
        const syInvalid = Math.max(
            1.0,
            downHeight > 0
                ? Math.min(
                    smallBandBoost(downHeight, targetSy),
                    chartHeightDown / Math.max(1e-6, downHeight)
                  )
                : 1.0
        );
        const sxClose = 3.0;
        const sxOngoing = 1.0; // no left-right growth for middle band
        const sxInvalid = 3.0;
        const pivotClose = axisY - chartHeightUpOngoing; // bottom of closing band
        const pivotOngoing = axisY - (chartHeightUpOngoing / 2); // center of ongoing band
        const pivotInvalid = axisY + invalidAxisGap;     // baseline offset for invalid

        overviewSvg.selectAll('.overview-stack-segment')
            .filter(s => s.binIndex === binIndex && (
                bandKind ? s.kind === bandKind : true
            ))
            .transition().duration(140)
            .attr('transform', s => {
                const cx = s.x + s.width / 2;
                const sy = (s.kind === 'closing') ? syClose : (s.kind === 'ongoing' ? syOngoing : syInvalid);
                const sx = (s.kind === 'closing') ? sxClose : (s.kind === 'ongoing' ? sxOngoing : sxInvalid);
                const py = (s.kind === 'closing') ? pivotClose : (s.kind === 'ongoing' ? pivotOngoing : pivotInvalid);
                return `translate(${cx},${py}) scale(${sx},${sy}) translate(${-cx},${-py})`;
            })
            .attr('stroke', 'none')
            .attr('stroke-width', 0);
    };
    const resetBinBand = (binIndex, bandKind) => {
        overviewSvg.selectAll('.overview-stack-segment')
            .filter(s => s.binIndex === binIndex && (
                bandKind ? s.kind === bandKind : true
            ))
            .transition().duration(180)
            .attr('transform', null)
            .attr('stroke', '#ffffff')
            .attr('stroke-width', 0.5);
    };

    // Create separate groups so we can control layering: invalid (bottom), closing (top band), ongoing (middle, on top of axis)
    const gInvalid = overviewSvg.append('g').attr('class', 'overview-group-invalid');
    const gClosing = overviewSvg.append('g').attr('class', 'overview-group-closing');
    const gOngoing = overviewSvg.append('g').attr('class', 'overview-group-ongoing');

    const renderSegsInto = (groupSel, data) => groupSel
        .selectAll('.overview-stack-segment')
        .data(data)
        .enter().append('rect')
        .attr('class', 'overview-stack-segment')
        .attr('x', d => d.x)
        .attr('y', d => d.y)
        .attr('width', d => d.width)
        .attr('height', d => Math.max(1, d.height))
        .attr('fill', d => d.kind === 'invalid' ? (invalidFlowColors[d.reason] || '#6c757d') : (d.kind === 'closing' ? (closeColors[d.closeType] || '#6c757d') : (ongoingColors[d.closeType] || '#6c757d')))
        .attr('stroke', '#ffffff')
        .attr('stroke-width', 0.5)
        .attr('vector-effect', 'non-scaling-stroke')
        .style('cursor', 'default')
        // Make hovering a segment amplify only its band
        .on('mouseover', (event, d) => amplifyBinBand(d.binIndex, d.kind))
        .on('mouseout', (event, d) => resetBinBand(d.binIndex, d.kind))
        .on('click', async (event, d) => {
            // Populate flow list with the flows represented by this specific segment
            try {
                const binIndex = d.binIndex;
                const binStartTime = timeExtent[0] + binIndex * timeBinSize;
                const binEndTime = binStartTime + timeBinSize;

                console.log('[OverviewClick] ========================================');
                console.log('[OverviewClick] DEBUGGING BIN CLICK');
                console.log('[OverviewClick] Clicked bin index:', binIndex);
                console.log('[OverviewClick] timeExtent:', timeExtent);
                console.log('[OverviewClick] timeBinSize:', timeBinSize);
                console.log('[OverviewClick] Calculated binStartTime:', binStartTime);
                console.log('[OverviewClick] Calculated binEndTime:', binEndTime);
                console.log('[OverviewClick] Duration (seconds):', (binEndTime - binStartTime) / 1e6);
                console.log('[OverviewClick] ========================================');

                if (typeof loadPacketBinRef === 'function') {
                    try { loadPacketBinRef(binIndex); } catch (_) {}
                }

                // Try to load actual flows from chunks if available
                let segFlows = Array.isArray(d.flows) ? d.flows : [];
                console.log('[OverviewClick] Segment click, bin:', binIndex, 'time range:', binStartTime, '-', binEndTime);
                console.log('[OverviewClick] loadChunksForTimeRangeRef available:', typeof loadChunksForTimeRangeRef === 'function');

                let loadingShown = false;
                if (typeof loadChunksForTimeRangeRef === 'function') {
                    try {
                        // Show loading indicator in modal (in the list container, not replacing the whole body)
                        showFlowListModal();
                        loadingShown = true;
                        const listContainer = document.getElementById('flowListModalList');
                        if (listContainer) {
                            listContainer.innerHTML = '<div style="padding: 20px; text-align: center; color: #666;">Loading flows...</div>';
                        }

                        // Load actual flows from chunks
                        console.log('[OverviewClick] Calling loadChunksForTimeRangeRef...');
                        const loadedFlows = await loadChunksForTimeRangeRef(binStartTime, binEndTime);
                        console.log('[OverviewClick] Loaded flows:', loadedFlows ? loadedFlows.length : 'null');
                        if (loadedFlows && loadedFlows.length > 0) {
                            segFlows = loadedFlows;
                        } else {
                            console.log('[OverviewClick] No flows loaded, using existing:', segFlows.length);
                        }
                    } catch (loadErr) {
                        console.warn('Failed to load flows from chunks:', loadErr);
                    }
                }

                console.log('[OverviewClick] Final segFlows count:', segFlows.length);
                if (typeof createFlowListRef === 'function') {
                    console.log('[OverviewClick] Calling createFlowListRef with', segFlows.length, 'flows');
                    try {
                        createFlowListRef(segFlows);
                        console.log('[OverviewClick] createFlowListRef completed');
                    } catch (err) {
                        console.error('[OverviewClick] createFlowListRef threw error:', err);
                    }
                } else {
                    // Fallback: show message if no flows available
                    const listContainer = document.getElementById('flowListModalList');
                    if (listContainer && segFlows.length === 0) {
                        listContainer.innerHTML = '<div style="padding: 20px; text-align: center; color: #999;">No detailed flow data available for this bin.</div>';
                    }
                }
                try { showFlowListModal(); } catch {}
            } catch (e) {
                console.warn('Failed to populate flow list from overview segment click:', e);
            }
        })
        .append('title')
        .text(d => {
            if (d.kind === 'invalid') return `${d.count} invalid flow(s)`;
            if (d.kind === 'closing') return `${d.count} ${d.closeType} close(s)`;
            return `${d.count} ${d.closeType} flow(s)`; // ongoing: open/incomplete
        });

    // Render invalid and closing segments first
    renderSegsInto(gInvalid, segments.filter(s => s.kind === 'invalid'));
    renderSegsInto(gClosing, segments.filter(s => s.kind === 'closing'));

    // Add generous transparent hit-areas per bin: full column width, full height.
    // We still amplify per-band, but we choose band based on mouse Y within the column.
    try {
        const hitGroup = overviewSvg.append('g').attr('class', 'overview-hit-areas');
        try { hitGroup.raise(); } catch {}
        const lastBandByBin = new Map();
        for (let i = 0; i < binCount; i++) {
            const binStartTime = timeExtent[0] + i * timeBinSize;
            const binEndTime = binStartTime + timeBinSize;
            const x0 = overviewXScale(binStartTime);
            const x1 = overviewXScale(binEndTime);
            // Use exact bin span for hit area to align with bars
            const widthPx = Math.max(1, x1 - x0);
            const x = x0;
            const axis = (overviewHeight - 30);

            // Collect flows for each band within this bin
            const mTop = binCloseMap.get(i) || new Map();
            const flowsClosing = Array.from(mTop.values()).flat();
            const mMid = binOngoingMap.get(i) || new Map();
            const flowsOngoing = Array.from(mMid.values()).flat();
            const mBot = binReasonMap.get(i) || new Map();
            const flowsInvalid = Array.from(mBot.values()).flat();

            // One full-height column hit area per bin
            const col = hitGroup.append('rect')
                .attr('class', 'overview-bin-hit column')
                .attr('x', x)
                .attr('y', 0)
                .attr('width', widthPx)
                .attr('height', overviewHeight)
                .style('fill', 'transparent')
                .style('pointer-events', 'all')
                .style('cursor', 'pointer')
                .datum({ binIndex: i, flows: { closing: flowsClosing, ongoing: flowsOngoing, invalid: flowsInvalid } })
                .on('mousemove', (event) => {
                    // Determine band by mouse Y within the column
                    const p = d3.pointer(event, overviewSvg.node());
                    const y = p ? p[1] : 0;
                    let band = 'invalid';
                    if (y < axis - chartHeightUpOngoing) band = 'closing';
                    else if (y < axis) band = 'ongoing';
                    const prev = lastBandByBin.get(i);
                    if (prev !== band) {
                        if (prev) resetBinBand(i, prev);
                        amplifyBinBand(i, band);
                        lastBandByBin.set(i, band);
                    }
                })
                .on('mouseout', () => {
                    const prev = lastBandByBin.get(i);
                    if (prev) resetBinBand(i, prev);
                    lastBandByBin.delete(i);
                })
                .on('click', async (event, d) => {
                    // Populate flow list based on the last hovered band for this bin
                    try {
                        const binIndex = i;
                        const binStartTime = timeExtent[0] + binIndex * timeBinSize;
                        const binEndTime = binStartTime + timeBinSize;
                        const band = lastBandByBin.get(i) || 'invalid';

                        if (typeof loadPacketBinRef === 'function') {
                            try { loadPacketBinRef(binIndex); } catch (_) {}
                        }

                        // Try to load actual flows from chunks if available
                        let flows = (d && d.flows && Array.isArray(d.flows[band])) ? d.flows[band] : [];
                        console.log('[OverviewClick] Column click, bin:', binIndex, 'band:', band, 'time range:', binStartTime, '-', binEndTime);
                        console.log('[OverviewClick] loadChunksForTimeRangeRef available:', typeof loadChunksForTimeRangeRef === 'function');

                        let loadingShown = false;
                        if (typeof loadChunksForTimeRangeRef === 'function') {
                            try {
                                // Show loading indicator in modal (in the list container, not replacing the whole body)
                                showFlowListModal();
                                loadingShown = true;
                                const listContainer = document.getElementById('flowListModalList');
                                if (listContainer) {
                                    listContainer.innerHTML = '<div style="padding: 20px; text-align: center; color: #666;">Loading flows...</div>';
                                }

                                // Load actual flows from chunks
                                console.log('[OverviewClick] Calling loadChunksForTimeRangeRef...');
                                const loadedFlows = await loadChunksForTimeRangeRef(binStartTime, binEndTime);
                                console.log('[OverviewClick] Loaded flows:', loadedFlows ? loadedFlows.length : 'null');
                                if (loadedFlows && loadedFlows.length > 0) {
                                    // Filter loaded flows by the selected band type
                                    console.log('[OverviewClick] Filtering for band:', band);
                                    console.log('[OverviewClick] Sample flow closeTypes:', loadedFlows.slice(0, 5).map(f => f.closeType));
                                    if (band === 'closing') {
                                        flows = loadedFlows.filter(f => f && (f.closeType === 'graceful' || f.closeType === 'abortive'));
                                    } else if (band === 'ongoing') {
                                        flows = loadedFlows.filter(f => f && !f.invalidReason && f.closeType !== 'invalid' &&
                                            f.closeType !== 'graceful' && f.closeType !== 'abortive');
                                    } else { // invalid
                                        flows = loadedFlows.filter(f => f && (f.closeType === 'invalid' || f.state === 'invalid' || f.invalidReason));
                                    }
                                    console.log('[OverviewClick] After filter:', flows.length, 'flows');
                                }
                            } catch (loadErr) {
                                console.warn('Failed to load flows from chunks:', loadErr);
                            }
                        }

                        console.log('[OverviewClick] Final flows count:', flows.length);
                        console.log('[OverviewClick] createFlowListRef available:', typeof createFlowListRef);
                        if (typeof createFlowListRef === 'function') {
                            console.log('[OverviewClick] Calling createFlowListRef with', flows.length, 'flows');
                            try {
                                createFlowListRef(flows);
                                console.log('[OverviewClick] createFlowListRef completed');
                            } catch (err) {
                                console.error('[OverviewClick] createFlowListRef threw error:', err);
                            }
                        } else {
                            // Fallback: show message if no flows available
                            const listContainer = document.getElementById('flowListModalList');
                            if (listContainer && flows.length === 0) {
                                listContainer.innerHTML = '<div style="padding: 20px; text-align: center; color: #999;">No detailed flow data available for this bin.</div>';
                            }
                        }
                        try { showFlowListModal(); } catch {}
                    } catch (e) {
                        console.warn('Failed to populate flow list from overview column click:', e);
                    }
                });
        }
    } catch {}

    // Note: Flow legends now displayed horizontally above the chart instead of in sidebar

    const overviewXAxis = d3.axisBottom(overviewXScale)
        .tickFormat(d => {
            const timestampInt = Math.floor(d);
            const date = new Date(timestampInt / 1000);
            return date.toISOString().split('T')[1].split('.')[0];
        });

    // Move the time axis to the center of the ongoing band
    const timeAxisY = (axisY - (chartHeightUpOngoing / 2));
    // Draw axis below ongoing group so ongoing bars appear on top
    const axisGroup = overviewSvg.append('g')
        .attr('class', 'overview-axis')
        .attr('transform', `translate(0,${timeAxisY})`)
        .call(overviewXAxis);

    // Ensure ongoing is rendered above axis by moving the group to front
    renderSegsInto(gOngoing, segments.filter(s => s.kind === 'ongoing'));
    try { gOngoing.raise(); } catch {}

    const bandTop = overviewHeight - 4;
    const bandBottom = overviewHeight;
    overviewBrush = d3.brushX()
        .extent([[0, bandTop], [overviewWidth, bandBottom]])
        .on('brush end', brushed);

    overviewSvg.append('g').attr('class', 'brush').call(overviewBrush);
    // Disable pointer events on brush overlay so clicks can pass through to bars
    overviewSvg.select('.brush .overlay').style('pointer-events', 'none');
    // Initialize brush selection to match the CURRENT zoom domain (not full extent)
    // Set flag to prevent this initialization from triggering applyZoomDomain
    isUpdatingFromZoom = true;
    try {
        // Get current domain from main chart if available, otherwise use full extent
        const currentDomain = getCurrentDomainRef ? getCurrentDomainRef() : null;
        const domainToUse = (currentDomain && currentDomain[0] !== undefined && currentDomain[1] !== undefined)
            ? currentDomain
            : timeExtent;
        const x0 = Math.max(0, Math.min(overviewWidth, overviewXScale(domainToUse[0])));
        const x1 = Math.max(0, Math.min(overviewWidth, overviewXScale(domainToUse[1])));
        const brushSel = overviewSvg.select('.brush');
        if (brushSel && !brushSel.empty()) {
            overviewSvg.select('.brush').call(overviewBrush.move, [x0, x1]);
        }
    } catch (e) {
        // Fallback to full selection if computation fails
        try { overviewSvg.select('.brush').call(overviewBrush.move, [0, overviewWidth]); } catch(_) {}
    } finally {
        isUpdatingFromZoom = false;
    }

    const lineY = overviewHeight - 1;
    if (!overviewSvg.select('.overview-custom').node()) {
        const custom = overviewSvg.append('g').attr('class', 'overview-custom');
        custom.append('line').attr('class', 'overview-window-line').attr('x1', 0).attr('x2', Math.max(0, overviewWidth)).attr('y1', lineY).attr('y2', lineY);
        custom.append('circle').attr('class', 'overview-handle left').attr('r', 6).attr('cx', 0).attr('cy', lineY);
        custom.append('circle').attr('class', 'overview-handle right').attr('r', 6).attr('cx', Math.max(0, overviewWidth)).attr('cy', lineY);
        custom.append('rect').attr('class', 'overview-window-grab').attr('x', 0).attr('y', lineY - 8).attr('width', overviewWidth).attr('height', 16);

        const getSel = () => d3.brushSelection(overviewSvg.select('.brush').node()) || [0, overviewWidth];
        const moveBrushTo = (x0, x1) => {
            x0 = Math.max(0, Math.min(overviewWidth, x0));
            x1 = Math.max(0, Math.min(overviewWidth, x1));
            if (x1 <= x0) x1 = Math.min(overviewWidth, x0 + 1);
            overviewSvg.select('.brush').call(overviewBrush.move, [x0, x1]);
        };
        const updateCustomFromSel = () => {
            const [x0, x1] = getSel();
            const lineY = overviewHeight - 1;
            custom.select('.overview-window-line').attr('x1', x0).attr('x2', x1).attr('y1', lineY).attr('y2', lineY);
            custom.select('.overview-handle.left').attr('cx', x0).attr('cy', lineY);
            custom.select('.overview-handle.right').attr('cx', x1).attr('cy', lineY);
            custom.select('.overview-window-grab').attr('x', x0).attr('y', lineY - 8).attr('width', Math.max(1, x1 - x0)).attr('height', 16);
        };
        updateCustomFromSel();
        custom.select('.overview-handle.left').call(d3.drag().on('drag', (event) => { const x0 = event.x; const [, x1] = getSel(); moveBrushTo(x0, x1); updateCustomFromSel(); }));
        custom.select('.overview-handle.right').call(d3.drag().on('drag', (event) => { const x1 = event.x; const [x0] = getSel(); moveBrushTo(x0, x1); updateCustomFromSel(); }));
        custom.select('.overview-window-grab').call(d3.drag().on('drag', (event) => { const [x0, x1] = getSel(); moveBrushTo(x0 + event.dx, x1 + event.dx); updateCustomFromSel(); }));
    }

    // Create horizontal flow legend above the chart
    try {
        createOverviewFlowLegend({
            svg: overviewSvg,
            width: overviewWidth,
            height: overviewHeight,
            flowColors: flowColors,
            flows: allFlows,
            hiddenInvalidReasons: hiddenInvalidReasonsRef,
            hiddenCloseTypes: hiddenCloseTypesRef,
            d3: d3,
            onToggleReason: (reason) => {
                // Filter flows by invalid reason and populate flow list
                const allFlows = getCurrentFlowsRef();
                const filteredFlows = allFlows.filter(f => {
                    if (!f) return false;
                    const fReason = f.invalidReason;
                    if (fReason && fReason === reason) return true;
                    if (!fReason && (f.closeType === 'invalid' || f.state === 'invalid') && reason === 'unknown_invalid') return true;
                    return false;
                });
                
                if (typeof createFlowListRef === 'function') {
                    createFlowListRef(filteredFlows);
                }
                try { showFlowListModal(); } catch {}
            },
            onToggleCloseType: (closeType) => {
                // Filter flows by close type and populate flow list
                const allFlows = getCurrentFlowsRef();
                const filteredFlows = allFlows.filter(f => {
                    if (!f) return false;
                    if (closeType === 'open') {
                        return f && !(f.closeType === 'invalid' || f.state === 'invalid' || !!f.invalidReason) && 
                               !(f.closeType === 'graceful' || f.closeType === 'abortive') &&
                               (f.establishmentComplete === true || f.state === 'established' || f.state === 'data_transfer');
                    }
                    return f.closeType === closeType;
                });
                
                if (typeof createFlowListRef === 'function') {
                    createFlowListRef(filteredFlows);
                }
                try { showFlowListModal(); } catch {}
            }
        });
    } catch (error) {
        console.warn('Failed to create overview flow legend:', error);
    }

    try { updateOverviewInvalidVisibility(); } catch {}

    // Ensure brush visuals reflect current zoom domain after creating overview
    try { updateBrushFromZoom(); } catch (_) {}
}

/**
 * Create overview chart directly from pre-aggregated IP pair bin data.
 * This is the fast path that skips flow iteration and uses ip_pair_overview.json.
 *
 * @param {Object} pairOverview - The ip_pair_overview.json data
 * @param {Array} selectedIPs - Array of selected IP addresses
 * @param {Object} options - Chart options { timeExtent, width, margins }
 */
export function createOverviewFromPairs(pairOverview, selectedIPs, options) {
    const d3 = d3Ref;
    if (!d3) {
        console.error('[OverviewChart] d3Ref is not set! initOverview may not have been called.');
        return;
    }

    const { timeExtent, width, margins } = options;
    console.log(`[OverviewChart] createOverviewFromPairs called with ${selectedIPs.length} IPs, timeExtent:`, timeExtent);

    d3.select('#overview-chart').html('');
    const container = document.getElementById('overview-container');
    if (container) container.style.display = 'block';

    // Build selected pair keys
    const selectedPairs = new Set();
    for (let i = 0; i < selectedIPs.length; i++) {
        for (let j = i + 1; j < selectedIPs.length; j++) {
            const [a, b] = [selectedIPs[i], selectedIPs[j]].sort();
            selectedPairs.add(`${a}<->${b}`);
        }
    }
    console.log(`[OverviewChart] Looking for ${selectedPairs.size} IP pair combinations`);

    // Extract metadata
    const meta = pairOverview.meta;
    const columns = meta.columns || ['bin', 'graceful', 'abortive', 'ongoing', 'open',
        'rst_during_handshake', 'invalid_ack', 'invalid_synack',
        'incomplete_no_synack', 'incomplete_no_ack', 'unknown_invalid'];

    // Column indices (after bin index)
    const colIdx = {};
    columns.forEach((col, i) => { colIdx[col] = i; });

    // Aggregate data across selected pairs
    const binTotals = new Map(); // binIdx -> { graceful, abortive, ongoing, open, invalid: { reason: count } }

    for (const pairKey of selectedPairs) {
        const rows = pairOverview.pairs[pairKey];
        if (!rows) continue;

        for (const row of rows) {
            const binIdx = row[0];

            let totals = binTotals.get(binIdx);
            if (!totals) {
                totals = { graceful: 0, abortive: 0, ongoing: 0, open: 0, invalid: {} };
                binTotals.set(binIdx, totals);
            }

            // Add counts from this row
            totals.graceful += row[colIdx.graceful] || 0;
            totals.abortive += row[colIdx.abortive] || 0;
            totals.ongoing += row[colIdx.ongoing] || 0;
            totals.open += row[colIdx.open] || 0;

            // Invalid reasons
            const invalidReasons = ['rst_during_handshake', 'invalid_ack', 'invalid_synack',
                                   'incomplete_no_synack', 'incomplete_no_ack', 'unknown_invalid'];
            for (const reason of invalidReasons) {
                const count = row[colIdx[reason]] || 0;
                if (count > 0) {
                    totals.invalid[reason] = (totals.invalid[reason] || 0) + count;
                }
            }
        }
    }

    console.log(`[OverviewChart] Aggregated ${binTotals.size} bins with data`);

    // Chart layout (match createOverviewChart)
    const chartMargins = margins || (getChartMarginsRef ? getChartMarginsRef() : { left: 150, right: 120, top: 80, bottom: 50 });
    const legendHeight = 35;
    const overviewMargin = { top: 15 + legendHeight, right: chartMargins.right, bottom: 30, left: chartMargins.left };
    overviewWidth = Math.max(100, width);
    overviewHeight = 100;

    const overviewSvgContainer = d3.select('#overview-chart').append('svg')
        .attr('width', overviewWidth + overviewMargin.left + overviewMargin.right)
        .attr('height', overviewHeight + overviewMargin.top + overviewMargin.bottom);

    overviewSvg = overviewSvgContainer.append('g')
        .attr('transform', `translate(${overviewMargin.left},${overviewMargin.top})`);

    overviewXScale = d3.scaleLinear().domain(timeExtent).range([0, overviewWidth]);

    const binCount = meta.bin_count;
    const binWidthUs = meta.bin_width_us;
    const dataTimeStart = meta.time_start;

    // Layout heights
    const axisY = overviewHeight - 30;
    const chartHeightUp = Math.max(10, axisY - 6);
    const chartHeightUpOngoing = chartHeightUp * 0.45;
    const chartHeightUpClosing = chartHeightUp - chartHeightUpOngoing;
    const brushTopY = overviewHeight - 4;
    const invalidAxisGap = 6;
    const chartHeightDown = Math.max(6, brushTopY - axisY - 4);

    // Colors (match createOverviewChart)
    const closeColors = {
        graceful: (flowColors.closing && flowColors.closing.graceful) || '#8e44ad',
        abortive: (flowColors.closing && flowColors.closing.abortive) || '#c0392b'
    };
    const ongoingColors = {
        open: (flowColors.ongoing && flowColors.ongoing.open) || '#6c757d',
        incomplete: (flowColors.ongoing && flowColors.ongoing.incomplete) || '#adb5bd'
    };
    const invalidFlowColors = {
        'invalid_ack': (flowColors.invalid && flowColors.invalid['invalid_ack']) || d3.color(flagColors['ACK'] || '#27ae60').darker(0.5).formatHex(),
        'invalid_synack': (flowColors.invalid && flowColors.invalid['invalid_synack']) || d3.color(flagColors['SYN+ACK'] || '#f39c12').darker(0.5).formatHex(),
        'rst_during_handshake': (flowColors.invalid && flowColors.invalid['rst_during_handshake']) || d3.color(flagColors['RST'] || '#34495e').darker(0.5).formatHex(),
        'incomplete_no_synack': (flowColors.invalid && flowColors.invalid['incomplete_no_synack']) || d3.color(flagColors['SYN+ACK'] || '#f39c12').brighter(0.5).formatHex(),
        'incomplete_no_ack': (flowColors.invalid && flowColors.invalid['incomplete_no_ack']) || d3.color(flagColors['ACK'] || '#27ae60').brighter(0.5).formatHex(),
        'unknown_invalid': (flowColors.invalid && flowColors.invalid['unknown_invalid']) || d3.color(flagColors['OTHER'] || '#bdc3c7').darker(0.5).formatHex()
    };

    const invalidOrder = ['invalid_ack', 'rst_during_handshake', 'incomplete_no_synack',
                         'incomplete_no_ack', 'invalid_synack', 'unknown_invalid'];
    const closingTypes = ['graceful', 'abortive'];

    // Compute max for scaling
    let maxTotal = 0;
    for (const [, totals] of binTotals) {
        const closeTotal = totals.graceful + totals.abortive;
        const ongoingTotal = totals.ongoing + totals.open;
        const invalidTotal = Object.values(totals.invalid).reduce((a, b) => a + b, 0);
        maxTotal = Math.max(maxTotal, closeTotal, ongoingTotal, invalidTotal);
    }
    const sharedMax = Math.max(1, maxTotal);

    // Build segments
    const segments = [];
    const binTotalsClosing = new Map();
    const binTotalsOngoing = new Map();
    const binTotalsInvalid = new Map();

    for (let i = 0; i < binCount; i++) {
        const binStartTime = dataTimeStart + i * binWidthUs;
        const binEndTime = binStartTime + binWidthUs;

        // Skip bins outside the visible time extent
        if (binEndTime < timeExtent[0] || binStartTime > timeExtent[1]) continue;

        const x0 = overviewXScale(Math.max(binStartTime, timeExtent[0]));
        const x1 = overviewXScale(Math.min(binEndTime, timeExtent[1]));
        const widthPx = Math.max(1, x1 - x0);
        const baseX = x0;

        const totals = binTotals.get(i) || { graceful: 0, abortive: 0, ongoing: 0, open: 0, invalid: {} };

        // Store per-bin totals for hover effects
        binTotalsClosing.set(i, totals.graceful + totals.abortive);
        binTotalsOngoing.set(i, totals.ongoing + totals.open);
        binTotalsInvalid.set(i, Object.values(totals.invalid).reduce((a, b) => a + b, 0));

        // Closing types (top band)
        let yTop = axisY - chartHeightUpOngoing;
        for (const t of closingTypes) {
            const count = totals[t];
            if (count === 0) continue;
            const h = (count / sharedMax) * chartHeightUpClosing;
            yTop -= h;
            segments.push({
                kind: 'closing', closeType: t, reason: null,
                x: baseX, y: yTop, width: widthPx, height: h,
                count, flows: [], binIndex: i, binStart: binStartTime, binEnd: binEndTime
            });
        }

        // Ongoing types (middle band)
        const centerY = axisY - (chartHeightUpOngoing / 2);
        if (totals.open > 0) {
            const h = (totals.open / sharedMax) * (chartHeightUpOngoing / 2);
            segments.push({
                kind: 'ongoing', closeType: 'open', reason: null,
                x: baseX, y: centerY - h, width: widthPx, height: h,
                count: totals.open, flows: [], binIndex: i, binStart: binStartTime, binEnd: binEndTime
            });
        }
        if (totals.ongoing > 0) {
            const h = (totals.ongoing / sharedMax) * (chartHeightUpOngoing / 2);
            segments.push({
                kind: 'ongoing', closeType: 'incomplete', reason: null,
                x: baseX, y: centerY, width: widthPx, height: h,
                count: totals.ongoing, flows: [], binIndex: i, binStart: binStartTime, binEnd: binEndTime
            });
        }

        // Invalid types (bottom band)
        let yBottom = axisY + invalidAxisGap;
        for (const reason of invalidOrder) {
            const count = totals.invalid[reason] || 0;
            if (count === 0) continue;
            const h = (count / sharedMax) * chartHeightDown;
            segments.push({
                kind: 'invalid', reason, closeType: null,
                x: baseX, y: yBottom, width: widthPx, height: h,
                count, flows: [], binIndex: i, binStart: binStartTime, binEnd: binEndTime
            });
            yBottom += h;
        }
    }

    console.log(`[OverviewChart] Created ${segments.length} segments for rendering`);

    // Amplify/reset functions (simplified from createOverviewChart)
    const amplifyBinBand = (binIndex, bandKind) => {
        const targetSy = 1.8;
        overviewSvg.selectAll('.overview-stack-segment')
            .filter(s => s.binIndex === binIndex && (!bandKind || s.kind === bandKind))
            .transition().duration(140)
            .attr('transform', s => {
                const cx = s.x + s.width / 2;
                const sy = targetSy;
                const sx = s.kind === 'ongoing' ? 1.0 : 3.0;
                const py = s.kind === 'closing' ? (axisY - chartHeightUpOngoing)
                         : (s.kind === 'ongoing' ? (axisY - chartHeightUpOngoing / 2)
                         : (axisY + invalidAxisGap));
                return `translate(${cx},${py}) scale(${sx},${sy}) translate(${-cx},${-py})`;
            })
            .attr('stroke', 'none')
            .attr('stroke-width', 0);
    };

    const resetBinBand = (binIndex, bandKind) => {
        overviewSvg.selectAll('.overview-stack-segment')
            .filter(s => s.binIndex === binIndex && (!bandKind || s.kind === bandKind))
            .transition().duration(180)
            .attr('transform', null)
            .attr('stroke', '#ffffff')
            .attr('stroke-width', 0.5);
    };

    // Create layer groups
    const gInvalid = overviewSvg.append('g').attr('class', 'overview-group-invalid');
    const gClosing = overviewSvg.append('g').attr('class', 'overview-group-closing');
    const gOngoing = overviewSvg.append('g').attr('class', 'overview-group-ongoing');

    const renderSegsInto = (groupSel, data) => groupSel
        .selectAll('.overview-stack-segment')
        .data(data)
        .enter().append('rect')
        .attr('class', 'overview-stack-segment')
        .attr('x', d => d.x)
        .attr('y', d => d.y)
        .attr('width', d => d.width)
        .attr('height', d => Math.max(1, d.height))
        .attr('fill', d => d.kind === 'invalid' ? (invalidFlowColors[d.reason] || '#6c757d')
                        : (d.kind === 'closing' ? (closeColors[d.closeType] || '#6c757d')
                        : (ongoingColors[d.closeType] || '#6c757d')))
        .attr('stroke', '#ffffff')
        .attr('stroke-width', 0.5)
        .attr('vector-effect', 'non-scaling-stroke')
        .style('cursor', 'pointer')
        .on('mouseover', (event, d) => amplifyBinBand(d.binIndex, d.kind))
        .on('mouseout', (event, d) => resetBinBand(d.binIndex, d.kind))
        .on('click', async (event, d) => {
            // Load actual flows from chunks on demand
            try {
                const binStart = d.binStart;
                const binEnd = d.binEnd;
                console.log(`[OverviewClick] Bin click, loading flows for time range: ${binStart} - ${binEnd}`);

                if (typeof loadChunksForTimeRangeRef === 'function') {
                    showFlowListModal();
                    const listContainer = document.getElementById('flowListModalList');
                    if (listContainer) {
                        listContainer.innerHTML = '<div style="padding: 20px; text-align: center; color: #666;">Loading flows...</div>';
                    }

                    const loadedFlows = await loadChunksForTimeRangeRef(binStart, binEnd);
                    if (loadedFlows && loadedFlows.length > 0 && typeof createFlowListRef === 'function') {
                        // Filter by band type
                        let filteredFlows = loadedFlows;
                        if (d.kind === 'closing') {
                            filteredFlows = loadedFlows.filter(f => f && (f.closeType === 'graceful' || f.closeType === 'abortive'));
                        } else if (d.kind === 'ongoing') {
                            filteredFlows = loadedFlows.filter(f => f && !f.invalidReason && f.closeType !== 'invalid' &&
                                f.closeType !== 'graceful' && f.closeType !== 'abortive');
                        } else {
                            filteredFlows = loadedFlows.filter(f => f && (f.closeType === 'invalid' || f.state === 'invalid' || f.invalidReason));
                        }
                        createFlowListRef(filteredFlows);
                    }
                }
            } catch (e) {
                console.warn('Failed to load flows on click:', e);
            }
        })
        .append('title')
        .text(d => {
            if (d.kind === 'invalid') return `${d.count} invalid flow(s) (${d.reason})`;
            if (d.kind === 'closing') return `${d.count} ${d.closeType} close(s)`;
            return `${d.count} ${d.closeType} flow(s)`;
        });

    // Render segments
    renderSegsInto(gInvalid, segments.filter(s => s.kind === 'invalid'));
    renderSegsInto(gClosing, segments.filter(s => s.kind === 'closing'));

    // Add time axis (at center of ongoing band)
    const overviewXAxis = d3.axisBottom(overviewXScale)
        .tickFormat(d => {
            const timestampInt = Math.floor(d);
            const date = new Date(timestampInt / 1000);
            return date.toISOString().split('T')[1].split('.')[0];
        });

    const timeAxisY = axisY - (chartHeightUpOngoing / 2);
    overviewSvg.append('g')
        .attr('class', 'overview-axis')
        .attr('transform', `translate(0,${timeAxisY})`)
        .call(overviewXAxis);

    // Render ongoing on top of axis
    renderSegsInto(gOngoing, segments.filter(s => s.kind === 'ongoing'));
    try { gOngoing.raise(); } catch {}

    // Add brush
    const bandTop = overviewHeight - 4;
    const bandBottom = overviewHeight;
    overviewBrush = d3.brushX()
        .extent([[0, bandTop], [overviewWidth, bandBottom]])
        .on('brush end', brushed);

    overviewSvg.append('g').attr('class', 'brush').call(overviewBrush);
    // Disable pointer events on brush overlay so clicks can pass through to bars
    overviewSvg.select('.brush .overlay').style('pointer-events', 'none');

    // Initialize brush selection
    isUpdatingFromZoom = true;
    try {
        const currentDomain = getCurrentDomainRef ? getCurrentDomainRef() : null;
        const domainToUse = (currentDomain && currentDomain[0] !== undefined && currentDomain[1] !== undefined)
            ? currentDomain : timeExtent;
        const x0 = Math.max(0, Math.min(overviewWidth, overviewXScale(domainToUse[0])));
        const x1 = Math.max(0, Math.min(overviewWidth, overviewXScale(domainToUse[1])));
        overviewSvg.select('.brush').call(overviewBrush.move, [x0, x1]);
    } catch (e) {
        try { overviewSvg.select('.brush').call(overviewBrush.move, [0, overviewWidth]); } catch(_) {}
    } finally {
        isUpdatingFromZoom = false;
    }

    // Add custom brush handles
    const lineY = overviewHeight - 1;
    const custom = overviewSvg.append('g').attr('class', 'overview-custom');
    custom.append('line').attr('class', 'overview-window-line').attr('x1', 0).attr('x2', overviewWidth).attr('y1', lineY).attr('y2', lineY);
    custom.append('circle').attr('class', 'overview-handle left').attr('r', 6).attr('cx', 0).attr('cy', lineY);
    custom.append('circle').attr('class', 'overview-handle right').attr('r', 6).attr('cx', overviewWidth).attr('cy', lineY);
    custom.append('rect').attr('class', 'overview-window-grab').attr('x', 0).attr('y', lineY - 8).attr('width', overviewWidth).attr('height', 16);

    const getSel = () => d3.brushSelection(overviewSvg.select('.brush').node()) || [0, overviewWidth];
    const moveBrushTo = (x0, x1) => {
        x0 = Math.max(0, Math.min(overviewWidth, x0));
        x1 = Math.max(0, Math.min(overviewWidth, x1));
        if (x1 <= x0) x1 = Math.min(overviewWidth, x0 + 1);
        overviewSvg.select('.brush').call(overviewBrush.move, [x0, x1]);
    };
    const updateCustomFromSel = () => {
        const [x0, x1] = getSel();
        custom.select('.overview-window-line').attr('x1', x0).attr('x2', x1);
        custom.select('.overview-handle.left').attr('cx', x0);
        custom.select('.overview-handle.right').attr('cx', x1);
        custom.select('.overview-window-grab').attr('x', x0).attr('width', Math.max(1, x1 - x0));
    };
    updateCustomFromSel();

    custom.select('.overview-handle.left').call(d3.drag().on('drag', (event) => {
        const [, x1] = getSel(); moveBrushTo(event.x, x1); updateCustomFromSel();
    }));
    custom.select('.overview-handle.right').call(d3.drag().on('drag', (event) => {
        const [x0] = getSel(); moveBrushTo(x0, event.x); updateCustomFromSel();
    }));
    custom.select('.overview-window-grab').call(d3.drag().on('drag', (event) => {
        const [x0, x1] = getSel(); moveBrushTo(x0 + event.dx, x1 + event.dx); updateCustomFromSel();
    }));

    // Create legend (build synthetic flow counts for legend display)
    try {
        let totalGraceful = 0, totalAbortive = 0, totalOpen = 0, totalOngoing = 0;
        const invalidCounts = {};
        for (const [, totals] of binTotals) {
            totalGraceful += totals.graceful;
            totalAbortive += totals.abortive;
            totalOpen += totals.open;
            totalOngoing += totals.ongoing;
            for (const [reason, count] of Object.entries(totals.invalid)) {
                invalidCounts[reason] = (invalidCounts[reason] || 0) + count;
            }
        }

        // Build synthetic flows for legend counts (minimal structure)
        const syntheticFlows = [];
        for (let i = 0; i < totalGraceful; i++) syntheticFlows.push({ closeType: 'graceful' });
        for (let i = 0; i < totalAbortive; i++) syntheticFlows.push({ closeType: 'abortive' });
        for (let i = 0; i < totalOpen; i++) syntheticFlows.push({ establishmentComplete: true });
        for (let i = 0; i < totalOngoing; i++) syntheticFlows.push({ state: 'connecting' });
        for (const [reason, count] of Object.entries(invalidCounts)) {
            for (let i = 0; i < count; i++) syntheticFlows.push({ invalidReason: reason });
        }

        createOverviewFlowLegend({
            svg: overviewSvg,
            width: overviewWidth,
            height: overviewHeight,
            flowColors: flowColors,
            flows: syntheticFlows,
            hiddenInvalidReasons: hiddenInvalidReasonsRef,
            hiddenCloseTypes: hiddenCloseTypesRef,
            d3: d3,
            onToggleReason: () => {},
            onToggleCloseType: () => {}
        });
    } catch (error) {
        console.warn('Failed to create overview flow legend:', error);
    }

    try { updateBrushFromZoom(); } catch (_) {}
}

export function updateBrushFromZoom() {
    if (isUpdatingFromBrush || !overviewBrush || !overviewXScale || !overviewSvg) return;
    isUpdatingFromZoom = true;
    const currentDomain = getCurrentDomain();
    const x0 = Math.max(0, Math.min(overviewWidth, overviewXScale(currentDomain[0])));
    const x1 = Math.max(0, Math.min(overviewWidth, overviewXScale(currentDomain[1])));
    if (x1 > x0) {
        overviewSvg.select('.brush').call(overviewBrush.move, [x0, x1]);
        try { updateCustomFromZoom(x0, x1); } catch {}
    }
    isUpdatingFromZoom = false;
}

export function setBrushUpdating(flag) {
    isUpdatingFromBrush = !!flag;
}

function updateCustomFromZoom(x0, x1) {
    const custom = overviewSvg.select('.overview-custom');
    if (custom && !custom.empty()) {
        const lineY = overviewHeight - 1;
        custom.select('.overview-window-line').attr('x1', x0).attr('x2', x1).attr('y1', lineY).attr('y2', lineY);
        custom.select('.overview-handle.left').attr('cx', x0).attr('cy', lineY);
        custom.select('.overview-handle.right').attr('cx', x1).attr('cy', lineY);
        custom.select('.overview-window-grab').attr('x', x0).attr('y', lineY - 8).attr('width', Math.max(1, x1 - x0)).attr('height', 16);
    }
}

function getCurrentDomain() {
    // Prefer the passed getCurrentDomainRef which handles intendedZoomDomain correctly
    if (getCurrentDomainRef) {
        const domain = getCurrentDomainRef();
        if (domain && domain.length === 2) return domain;
    }

    const timeExtent = getTimeExtentRef();
    // Fallback: read from global xScale on window if present
    if (window && window.__arc_x_domain__) return window.__arc_x_domain__;
    // Final fallback to full extent
    return timeExtent;
}

function brushed(event) {
    if (isUpdatingFromZoom) return; // Prevent circular updates
    if (!overviewXScale) return;
    const sel = event.selection;
    if (!sel) return;
    const [x0, x1] = sel;
    const newDomain = [overviewXScale.invert(x0), overviewXScale.invert(x1)];
    const d3 = d3Ref;
    const custom = overviewSvg && overviewSvg.select('.overview-custom');
    if (custom && !custom.empty()) {
        const lineY = overviewHeight - 1;
        custom.select('.overview-window-line').attr('x1', x0).attr('x2', x1).attr('y1', lineY).attr('y2', lineY);
        custom.select('.overview-handle.left').attr('cx', x0).attr('cy', lineY);
        custom.select('.overview-handle.right').attr('cx', x1).attr('cy', lineY);
        custom.select('.overview-window-grab').attr('x', x0).attr('y', lineY - 8).attr('width', Math.max(1, x1 - x0)).attr('height', 16);
    }
    applyZoomDomainRef(newDomain, 'brush');
}

/**
 * Refresh the flow overview chart with current flows.
 * Call this after IP selection changes to update the overview display.
 */
export function refreshFlowOverview() {
    if (!getTimeExtentRef || !getWidthRef) {
        console.log('[OverviewChart] Cannot refresh - missing references');
        return;
    }
    const timeExtent = getTimeExtentRef();
    const width = getWidthRef();
    const margins = getChartMarginsRef ? getChartMarginsRef() : { left: 150, right: 120, top: 80, bottom: 50 };

    // Get current flows from main chart (updated after IP selection)
    const currentFlows = getCurrentFlowsRef ? getCurrentFlowsRef() : [];
    console.log(`[OverviewChart] Refreshing with ${currentFlows.length} flows`);
    console.log('[OverviewChart] Using timeExtent:', timeExtent);
    console.log('[OverviewChart] Duration:', timeExtent ? (timeExtent[1] - timeExtent[0]) / 1e6 : 'N/A', 'seconds');

    // Re-create the overview chart with updated flows
    createOverviewChart(currentFlows, { timeExtent, width, margins });
}

/**
 * Create overview chart directly from pre-aggregated adaptive bin data.
 * This is an optimized path that avoids creating individual flow objects.
 *
 * @param {Object} adaptiveData - Data from AdaptiveOverviewLoader.getOverviewData()
 * @param {Object} options - Chart options
 * @param {[number,number]} options.timeExtent - Time range [start, end] in microseconds
 * @param {number} options.width - Chart width
 * @param {Object} options.margins - Chart margins
 */
export function createOverviewFromAdaptive(adaptiveData, { timeExtent, width, margins }) {
    console.log(`[OverviewChart] createOverviewFromAdaptive called with ${adaptiveData.bins.length} bins, resolution: ${adaptiveData.resolution}`);
    const d3 = d3Ref;
    if (!d3) {
        console.error('[OverviewChart] d3Ref is not set! initOverview may not have been called.');
        return;
    }

    d3.select('#overview-chart').html('');
    const container = document.getElementById('overview-container');
    if (container) container.style.display = 'block';

    // Use chart margins for alignment with main chart
    const chartMargins = margins || (getChartMarginsRef ? getChartMarginsRef() : { left: 150, right: 120, top: 80, bottom: 50 });
    const legendHeight = 35;
    const overviewMargin = { top: 15 + legendHeight, right: chartMargins.right, bottom: 30, left: chartMargins.left };
    overviewWidth = Math.max(100, width);
    overviewHeight = 100;

    const overviewSvgContainer = d3.select('#overview-chart').append('svg')
        .attr('width', overviewWidth + overviewMargin.left + overviewMargin.right)
        .attr('height', overviewHeight + overviewMargin.top + overviewMargin.bottom);

    overviewSvg = overviewSvgContainer.append('g')
        .attr('transform', `translate(${overviewMargin.left},${overviewMargin.top})`);

    overviewXScale = d3.scaleLinear().domain(timeExtent).range([0, overviewWidth]);

    // Define category mappings for the adaptive data
    const invalidReasons = ['rst_during_handshake', 'invalid_ack', 'invalid_synack', 'incomplete_no_synack', 'incomplete_no_ack', 'unknown_invalid'];
    const closingTypes = ['graceful', 'abortive'];
    const ongoingTypes = ['open', 'ongoing'];

    // Build color schemes (same as createOverviewChart)
    const invalidFlowColors = {
        'invalid_ack': flowColors.invalid?.invalid_ack || d3.color(flagColors['ACK'] || '#27ae60').darker(0.5).formatHex(),
        'invalid_synack': flowColors.invalid?.invalid_synack || d3.color(flagColors['SYN+ACK'] || '#f39c12').darker(0.5).formatHex(),
        'rst_during_handshake': flowColors.invalid?.rst_during_handshake || d3.color(flagColors['RST'] || '#34495e').darker(0.5).formatHex(),
        'incomplete_no_synack': flowColors.invalid?.incomplete_no_synack || d3.color(flagColors['SYN+ACK'] || '#f39c12').brighter(0.5).formatHex(),
        'incomplete_no_ack': flowColors.invalid?.incomplete_no_ack || d3.color(flagColors['ACK'] || '#27ae60').brighter(0.5).formatHex(),
        'unknown_invalid': flowColors.invalid?.unknown_invalid || d3.color(flagColors['OTHER'] || '#bdc3c7').darker(0.5).formatHex()
    };
    const closeColors = {
        graceful: flowColors.closing?.graceful || '#8e44ad',
        abortive: flowColors.closing?.abortive || '#c0392b'
    };
    const ongoingColors = {
        open: flowColors.ongoing?.open || '#6c757d',
        ongoing: flowColors.ongoing?.incomplete || '#adb5bd'
    };

    const axisY = overviewHeight - 30;
    const chartHeightUp = Math.max(10, axisY - 6);
    const chartHeightUpOngoing = chartHeightUp * 0.45;
    const chartHeightUpClosing = chartHeightUp - chartHeightUpOngoing;
    const brushTopY = overviewHeight - 4;
    const invalidAxisGap = 6;
    const chartHeightDown = Math.max(6, brushTopY - axisY - 4);

    // Determine present reasons for row layout
    const presentReasonsSet = new Set();
    for (const bin of adaptiveData.bins) {
        for (const reason of invalidReasons) {
            if (bin.counts[reason] > 0) presentReasonsSet.add(reason);
        }
    }
    const presentReasons = invalidReasons.filter(r => presentReasonsSet.has(r));
    const reasons = presentReasons.length ? presentReasons : ['unknown_invalid'];

    // Compute max values for scaling (per-band, not total sum)
    let maxTotal = 0;
    for (const bin of adaptiveData.bins) {
        const closeTotal = (bin.counts.graceful || 0) + (bin.counts.abortive || 0);
        const ongoingTotal = (bin.counts.open || 0) + (bin.counts.ongoing || 0);
        let invalidTotal = 0;
        for (const reason of invalidReasons) {
            invalidTotal += bin.counts[reason] || 0;
        }
        maxTotal = Math.max(maxTotal, closeTotal, ongoingTotal, invalidTotal);
    }
    const sharedMax = Math.max(1, maxTotal);

    // Build segments for rendering
    const segments = [];
    for (const bin of adaptiveData.bins) {
        // Skip bins outside the visible time extent
        if (bin.end < timeExtent[0] || bin.start > timeExtent[1]) continue;

        // Clamp bin positions to the time extent
        const x0 = overviewXScale(Math.max(bin.start, timeExtent[0]));
        const x1 = overviewXScale(Math.min(bin.end, timeExtent[1]));
        const widthPx = Math.max(1, x1 - x0);
        const baseX = x0;

        // Upward stacking: closing types (top band)
        let yTop = axisY - chartHeightUpOngoing;
        for (const t of closingTypes) {
            const count = bin.counts[t] || 0;
            if (count === 0) continue;
            const h = (count / sharedMax) * chartHeightUpClosing;
            yTop -= h;
            segments.push({
                kind: 'closing', closeType: t, reason: null,
                x: baseX, y: yTop, width: widthPx, height: h,
                count, flows: [], binIndex: bin.binIndex
            });
        }

        // Ongoing types (middle band)
        const centerY = axisY - (chartHeightUpOngoing / 2);
        for (const t of ongoingTypes) {
            const count = bin.counts[t] || 0;
            if (count === 0) continue;
            const h = (count / sharedMax) * (chartHeightUpOngoing / 2);
            const y = t === 'open' ? centerY - h : centerY;
            segments.push({
                kind: 'ongoing', closeType: t, reason: null,
                x: baseX, y, width: widthPx, height: h,
                count, flows: [], binIndex: bin.binIndex
            });
        }

        // Downward stacking: invalid reasons
        let yBottom = axisY + invalidAxisGap;
        for (const reason of reasons) {
            const count = bin.counts[reason] || 0;
            if (count === 0) continue;
            const h = (count / sharedMax) * chartHeightDown;
            segments.push({
                kind: 'invalid', reason, closeType: null,
                x: baseX, y: yBottom, width: widthPx, height: h,
                count, flows: [], binIndex: bin.binIndex
            });
            yBottom += h;
        }
    }

    // Render segments
    const getSegmentColor = (d) => {
        if (d.kind === 'invalid') return invalidFlowColors[d.reason] || '#999';
        if (d.kind === 'closing') return closeColors[d.closeType] || '#666';
        if (d.kind === 'ongoing') return ongoingColors[d.closeType] || '#888';
        return '#ccc';
    };

    // Helper functions for hover effects
    const amplifyBinBand = (binIndex, band) => {
        overviewSvg.selectAll('.overview-stack-segment')
            .filter(d => d.binIndex === binIndex && d.kind === band)
            .style('opacity', 1)
            .attr('stroke', '#333')
            .attr('stroke-width', 1.5);
    };
    const resetBinBand = (binIndex, band) => {
        overviewSvg.selectAll('.overview-stack-segment')
            .filter(d => d.binIndex === binIndex && d.kind === band)
            .style('opacity', 0.85)
            .attr('stroke', '#ffffff')
            .attr('stroke-width', 0.5);
    };

    overviewSvg.selectAll('.overview-stack-segment')
        .data(segments)
        .enter()
        .append('rect')
        .attr('class', d => `overview-stack-segment overview-${d.kind}`)
        .attr('x', d => d.x)
        .attr('y', d => d.y)
        .attr('width', d => d.width)
        .attr('height', d => Math.max(0.5, d.height))
        .attr('fill', getSegmentColor)
        .attr('stroke', '#ffffff')
        .attr('stroke-width', 0.5)
        .style('opacity', 0.85)
        .style('cursor', 'pointer')
        .on('mouseover', (event, d) => amplifyBinBand(d.binIndex, d.kind))
        .on('mouseout', (event, d) => resetBinBand(d.binIndex, d.kind))
        .on('click', async (event, d) => {
            // Load actual flows from chunks on demand
            try {
                const bin = adaptiveData.bins.find(b => b.binIndex === d.binIndex);
                const binStart = bin ? bin.start : timeExtent[0];
                const binEnd = bin ? bin.end : timeExtent[1];
                console.log(`[AdaptiveOverviewClick] Bin click, loading flows for time range: ${binStart} - ${binEnd}`);

                if (typeof loadPacketBinRef === 'function') {
                    try { loadPacketBinRef(d.binIndex); } catch (_) {}
                }

                if (typeof loadChunksForTimeRangeRef === 'function') {
                    showFlowListModal();
                    const listContainer = document.getElementById('flowListModalList');
                    if (listContainer) {
                        listContainer.innerHTML = '<div style="padding: 20px; text-align: center; color: #666;">Loading flows...</div>';
                    }

                    const loadedFlows = await loadChunksForTimeRangeRef(binStart, binEnd);
                    console.log('[AdaptiveOverviewClick] Loaded flows:', loadedFlows ? loadedFlows.length : 'null');

                    if (typeof createFlowListRef === 'function' && loadedFlows && loadedFlows.length > 0) {
                        createFlowListRef(loadedFlows);
                    } else if (listContainer) {
                        listContainer.innerHTML = '<div style="padding: 20px; text-align: center; color: #999;">No detailed flow data available for this bin.</div>';
                    }
                } else {
                    // No chunk loader available
                    showFlowListModal();
                    const listContainer = document.getElementById('flowListModalList');
                    if (listContainer) {
                        listContainer.innerHTML = `<div style="padding: 20px; text-align: center; color: #999;">
                            Bin ${d.binIndex}: ${d.count} ${d.kind} flows<br>
                            <small>Detailed flow data requires chunk loading</small>
                        </div>`;
                    }
                }
            } catch (err) {
                console.error('[AdaptiveOverviewClick] Error:', err);
            }
        });

    // Render axis line
    overviewSvg.append('line')
        .attr('class', 'overview-axis-line')
        .attr('x1', 0)
        .attr('x2', overviewWidth)
        .attr('y1', axisY)
        .attr('y2', axisY)
        .attr('stroke', '#666')
        .attr('stroke-width', 1);

    // Render time axis (use UTC to match main chart)
    const xAxis = d3.axisBottom(overviewXScale)
        .ticks(6)
        .tickFormat(d => {
            const date = new Date(d / 1000);
            return date.toISOString().substring(11, 19);
        });

    overviewSvg.append('g')
        .attr('class', 'overview-axis')
        .attr('transform', `translate(0,${overviewHeight - 5})`)
        .call(xAxis)
        .selectAll('text')
        .style('font-size', '9px');

    // Add resolution indicator
    overviewSvg.append('text')
        .attr('class', 'overview-resolution-label')
        .attr('x', overviewWidth - 5)
        .attr('y', 12)
        .attr('text-anchor', 'end')
        .style('font-size', '9px')
        .style('fill', '#888')
        .text(`Resolution: ${adaptiveData.resolution}`);

    // Initialize brush - use narrow band at bottom like original
    const bandTop = overviewHeight - 4;
    const bandBottom = overviewHeight;

    const brushed = (event) => {
        if (isUpdatingFromZoom) return;
        const sel = event.selection;
        if (!sel) return;
        isUpdatingFromBrush = true;
        const [x0, x1] = sel;
        const domain = [overviewXScale.invert(x0), overviewXScale.invert(x1)];

        // Update custom brush visualization
        const lineY = overviewHeight - 1;
        const custom = overviewSvg.select('.overview-custom');
        if (custom && !custom.empty()) {
            custom.select('.overview-window-line').attr('x1', x0).attr('x2', x1);
            custom.select('.overview-handle.left').attr('cx', x0);
            custom.select('.overview-handle.right').attr('cx', x1);
            custom.select('.overview-window-grab').attr('x', x0).attr('width', Math.max(1, x1 - x0));
        }

        if (applyZoomDomainRef) applyZoomDomainRef(domain, 'brush');
        isUpdatingFromBrush = false;
    };

    overviewBrush = d3.brushX()
        .extent([[0, bandTop], [overviewWidth, bandBottom]])
        .on('brush end', brushed);

    overviewSvg.append('g').attr('class', 'brush').call(overviewBrush);
    // Disable pointer events on brush overlay so clicks can pass through to bars
    overviewSvg.select('.brush .overlay').style('pointer-events', 'none');

    // Initialize brush selection
    isUpdatingFromZoom = true;
    try {
        const currentDomain = getCurrentDomainRef ? getCurrentDomainRef() : null;
        const domainToUse = (currentDomain && currentDomain[0] !== undefined && currentDomain[1] !== undefined)
            ? currentDomain
            : timeExtent;
        const x0 = Math.max(0, Math.min(overviewWidth, overviewXScale(domainToUse[0])));
        const x1 = Math.max(0, Math.min(overviewWidth, overviewXScale(domainToUse[1])));
        overviewSvg.select('.brush').call(overviewBrush.move, [x0, x1]);
    } catch (e) {
        try { overviewSvg.select('.brush').call(overviewBrush.move, [0, overviewWidth]); } catch(_) {}
    } finally {
        isUpdatingFromZoom = false;
    }

    // Add custom brush visualization (line + handles)
    const lineY = overviewHeight - 1;
    const custom = overviewSvg.append('g').attr('class', 'overview-custom');
    custom.append('line').attr('class', 'overview-window-line')
        .attr('x1', 0).attr('x2', overviewWidth).attr('y1', lineY).attr('y2', lineY)
        .attr('stroke', '#007bff').attr('stroke-width', 3);
    custom.append('circle').attr('class', 'overview-handle left')
        .attr('r', 6).attr('cx', 0).attr('cy', lineY)
        .attr('fill', '#007bff').attr('stroke', '#fff').attr('stroke-width', 2)
        .style('cursor', 'ew-resize');
    custom.append('circle').attr('class', 'overview-handle right')
        .attr('r', 6).attr('cx', overviewWidth).attr('cy', lineY)
        .attr('fill', '#007bff').attr('stroke', '#fff').attr('stroke-width', 2)
        .style('cursor', 'ew-resize');
    custom.append('rect').attr('class', 'overview-window-grab')
        .attr('x', 0).attr('y', lineY - 8).attr('width', overviewWidth).attr('height', 16)
        .attr('fill', 'transparent').style('cursor', 'move');

    // Wire up drag interactions for custom handles
    const getSel = () => d3.brushSelection(overviewSvg.select('.brush').node()) || [0, overviewWidth];
    const moveBrushTo = (x0, x1) => {
        x0 = Math.max(0, Math.min(overviewWidth, x0));
        x1 = Math.max(0, Math.min(overviewWidth, x1));
        if (x1 <= x0) x1 = Math.min(overviewWidth, x0 + 1);
        overviewSvg.select('.brush').call(overviewBrush.move, [x0, x1]);
    };
    const updateCustomFromSel = () => {
        const [x0, x1] = getSel();
        custom.select('.overview-window-line').attr('x1', x0).attr('x2', x1);
        custom.select('.overview-handle.left').attr('cx', x0);
        custom.select('.overview-handle.right').attr('cx', x1);
        custom.select('.overview-window-grab').attr('x', x0).attr('width', Math.max(1, x1 - x0));
    };
    updateCustomFromSel();

    custom.select('.overview-handle.left').call(d3.drag().on('drag', (event) => {
        const x0 = event.x; const [, x1] = getSel(); moveBrushTo(x0, x1); updateCustomFromSel();
    }));
    custom.select('.overview-handle.right').call(d3.drag().on('drag', (event) => {
        const x1 = event.x; const [x0] = getSel(); moveBrushTo(x0, x1); updateCustomFromSel();
    }));
    custom.select('.overview-window-grab').call(d3.drag().on('drag', (event) => {
        const [x0, x1] = getSel(); moveBrushTo(x0 + event.dx, x1 + event.dx); updateCustomFromSel();
    }));

    console.log(`[OverviewChart] Rendered ${segments.length} segments from adaptive data`);
}

export function updateOverviewInvalidVisibility() {
    if (!overviewSvg) return;
    const hiddenReasons = hiddenInvalidReasonsRef;
    const hiddenCloses = hiddenCloseTypesRef;
    const noReasonHidden = !hiddenReasons || hiddenReasons.size === 0;
    const noCloseHidden = !hiddenCloses || hiddenCloses.size === 0;
    
    // Update chart segments
    overviewSvg.selectAll('.overview-stack-segment')
        .style('display', d => {
            if (!d) return null;
            if (d.kind === 'invalid') {
                return (noReasonHidden || !d.reason || !hiddenReasons.has(d.reason)) ? null : 'none';
            }
            if (d.kind === 'closing' || d.kind === 'ongoing') {
                return (noCloseHidden || !d.closeType || !hiddenCloses.has(d.closeType)) ? null : 'none';
            }
            return null;
        })
        .style('opacity', d => {
            if (!d) return null;
            if (d.kind === 'invalid') {
                return (noReasonHidden || !d.reason || !hiddenReasons.has(d.reason)) ? null : 0;
            }
            if (d.kind === 'closing' || d.kind === 'ongoing') {
                return (noCloseHidden || !d.closeType || !hiddenCloses.has(d.closeType)) ? null : 0;
            }
            return null;
        });
    
    // Update legend to reflect hidden state
    overviewSvg.selectAll('.overview-flow-legend .legend-item')
        .style('opacity', function() {
            const item = d3Ref.select(this);
            const data = item.datum();
            if (!data) return 1.0;
            
            let hidden = false;
            if (data.type === 'invalid') {
                hidden = hiddenReasons && hiddenReasons.has(data.key);
            } else if (data.type === 'closing' || data.type === 'ongoing') {
                hidden = hiddenCloses && hiddenCloses.has(data.key);
            }
            return hidden ? 0.4 : 1.0;
        });
}

/**
 * Stub function for backward compatibility with multires_flows format.
 * The actual implementation would display pre-binned flow data from tcp_flow_detector_multires.py.
 * For chunked_flows format (tcp_data_loader_streaming.py), use createOverviewChart instead.
 */
export function createFlowOverviewChart(overviewBins, options) {
    console.warn('[OverviewChart] createFlowOverviewChart called but not fully implemented for this overview_chart.js version.');
    console.log('[OverviewChart] Use chunked_flows format (tcp_data_loader_streaming.py) which uses createOverviewChart instead.');

    // Fallback: if we have timeExtent and width, try to create a basic overview
    if (options && options.timeExtent && options.width) {
        // We can't display pre-binned data in this version, but we can at least not crash
        console.log('[OverviewChart] Received', overviewBins?.length || 0, 'pre-binned entries');
    }
}
