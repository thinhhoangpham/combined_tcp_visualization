// Extracted from ip_arc_diagram_3.html inline script
// This file contains all logic for the IP Connection Analysis visualization
import { initSidebar, createIPCheckboxes as sbCreateIPCheckboxes, filterIPList as sbFilterIPList, filterFlowList as sbFilterFlowList, updateFlagStats as sbUpdateFlagStats, updateIPStats as sbUpdateIPStats, createFlowListCapped as sbCreateFlowListCapped, updateTcpFlowStats as sbUpdateTcpFlowStats, updateGroundTruthStatsUI as sbUpdateGroundTruthStatsUI, wireSidebarControls as sbWireSidebarControls, showFlowProgress as sbShowFlowProgress, updateFlowProgress as sbUpdateFlowProgress, hideFlowProgress as sbHideFlowProgress, wireFlowListModalControls as sbWireFlowListModalControls, showCsvProgress as sbShowCsvProgress, updateCsvProgress as sbUpdateCsvProgress, hideCsvProgress as sbHideCsvProgress } from './sidebar.js';
import { renderInvalidLegend as sbRenderInvalidLegend, renderClosingLegend as sbRenderClosingLegend, drawFlagLegend as drawFlagLegendFromModule } from './legends.js';
import { initOverview, createOverviewChart, createOverviewFromPairs, createOverviewFromAdaptive, createFlowOverviewChart, updateBrushFromZoom, updateOverviewInvalidVisibility, setBrushUpdating, refreshFlowOverview } from './overview_chart.js';
import { FLOW_RECONSTRUCT_BATCH } from './config.js';
import {
    DEBUG, RADIUS_MIN, RADIUS_MAX, ROW_GAP, TOP_PAD,
    TCP_STATES, HANDSHAKE_TIMEOUT_MS, REORDER_WINDOW_PKTS, REORDER_WINDOW_MS,
    DEFAULT_FLAG_COLORS, FLAG_CURVATURE, PROTOCOL_MAP,
    DEFAULT_FLOW_COLORS, DEFAULT_EVENT_COLORS
} from './src/config/constants.js';
import {
    LOG, formatBytes, formatTimestamp, formatDuration,
    utcToEpochMicroseconds, epochMicrosecondsToUTC,
    makeConnectionKey, clamp, normalizeProtocolValue,
    createSmartTickFormatter
} from './src/utils/formatters.js';
import {
    classifyFlags, getFlagType, flagPhase, isFlagVisibleByPhase,
    has, isSYN, isSYNACK, isACKonly,
    getColoredFlagBadges, getTopFlags
} from './src/tcp/flags.js';
import { getVisiblePackets, computeBarWidthPx } from './src/data/binning.js';
import { AdaptiveOverviewLoader } from './src/data/adaptive-overview-loader.js';
import {
    computeTimeArcsRange,
    createSyntheticFlowsFromChunks,
    logSyntheticFlowRange,
    initializeAdaptiveLoader,
    loadFlowBinsFallback,
    loadIpPairOverview,
    updateFlowDataUI,
    calculateChartDimensions
} from './src/data/flow-data-handler.js';
import {
    reconstructFlowsFromCSVAsync,
    reconstructFlowsFromCSV,
    buildSelectedFlowKeySet as buildSelectedFlowKeySetFromModule,
    verifyFlowPacketConnection,
    exportFlowToCSV as exportFlowToCSVFromModule
} from './src/data/flowReconstruction.js';
import { renderCircles } from './src/rendering/circles.js';
import { renderBars, renderMarksForLayer } from './src/rendering/bars.js';
import { createTooltipHTML } from './src/rendering/tooltip.js';
import { arcPathGenerator } from './src/rendering/arcPath.js';
import {
    buildForceLayoutData,
    computeForceLayoutPositions as computeForceLayoutPositionsBase,
    applyForceLayoutPositions as applyForceLayoutPositionsBase
} from './src/layout/barForceLayout.js';
import { createZoomBehavior, applyZoomDomain as applyZoomDomainFromModule } from './src/interaction/zoom.js';
import { createDragReorderBehavior } from './src/interaction/dragReorder.js';
import { setupWindowResizeHandler as setupWindowResizeHandlerFromModule } from './src/interaction/resize.js';
import {
    loadGroundTruthData,
    filterGroundTruthByIPs,
    prepareGroundTruthBoxData,
    calculateGroundTruthStats
} from './src/groundTruth/groundTruth.js';
import {
    createPacketWorkerManager,
    applyVisibilityToDots
} from './src/workers/packetWorkerManager.js';
import {
    computeIPCounts,
    computeIPPositioning,
    applyIPPositioningToState
} from './src/layout/ipPositioning.js';
import {
    createSVGStructure,
    createBottomOverlay,
    renderIPRowLabels,
    resizeBottomOverlay
} from './src/rendering/svgSetup.js';
import {
    prepareInitialRenderData,
    performInitialRender,
    createRadiusScale
} from './src/rendering/initialRender.js';
import {
    createTimeArcsZoomHandler,
    createDurationLabelUpdater,
    clearZoomTimeouts
} from './src/interaction/timearcsZoomHandler.js';
import { createIPFilterController } from './src/interaction/ip-filter-controller.js';
import { tryLoadFlowList, getFlowListLoader } from './src/data/flow-list-loader.js';

// Multi-resolution support (optional - may not be available)
let getMultiResData = null;
let isMultiResAvailable = null;
let getCurrentResolution = null;
let setMultiResSelectedIPs = null;
let loadFlowDetailWithPackets = null;
let extractPacketsFromFlow = null;
let getChunkedFlowState = null;

// Try to dynamically import multi-resolution functions
try {
    const folderIntegration = await import('./folder_integration.js');
    getMultiResData = folderIntegration.getMultiResData;
    isMultiResAvailable = folderIntegration.isMultiResAvailable;
    getCurrentResolution = folderIntegration.getCurrentResolution;
    setMultiResSelectedIPs = folderIntegration.setMultiResSelectedIPs;
    loadFlowDetailWithPackets = folderIntegration.loadFlowDetailWithPackets;
    extractPacketsFromFlow = folderIntegration.extractPacketsFromFlow;
    getChunkedFlowState = folderIntegration.getChunkedFlowState;
    console.log('Multi-resolution support loaded');
} catch (err) {
    console.log('Multi-resolution support not available:', err.message);
}

// Multi-resolution state
let useMultiRes = false;  // Whether to use multi-resolution data
let currentResolutionLevel = null;  // Current resolution: 'seconds', 'milliseconds', 'raw', or null
let isInitialResolutionLoad = true;  // Only sync with overview on initial load, then allow free zoom

// --- Web Worker for packet filtering ---
let workerManager = null;

function initializeWorkerManager() {
    workerManager = createPacketWorkerManager({
        onVisibilityApplied: (mask) => {
            if (!mainGroup) {
                console.warn('Worker visibility applied but mainGroup not available');
                return;
            }
            const dots = mainGroup.selectAll('.direction-dot').nodes();
            if (DEBUG && dots.length !== mask.length) {
                console.warn(`Worker mask/dots mismatch: mask=${mask.length}, dots=${dots.length}. This may indicate DOM was updated after worker init.`);
            }
            applyVisibilityToDots(mask, dots, {
                onComplete: () => {
                    try { applyInvalidReasonFilter(); } catch(e) { logCatchError('applyInvalidReasonFilter', e); }
                }
            });
        },
        onError: (error) => {
            console.error('Worker error, falling back to legacy filtering:', error);
            legacyFilterPacketsBySelectedFlows();
        }
    });
}

// --- Error logging helper for catch blocks ---
// Provides consistent error logging with context for debugging
// Usage: catch(e) { logCatchError('functionName', e); }
function logCatchError(context, error) {
    if (DEBUG) {
        console.warn(`[${context}] Error caught:`, error?.message || error);
    }
}

function reinitializeWorkerIfNeeded(packets) {
    if (workerManager && packets) {
        try {
            workerManager.initPackets(packets);
        } catch (err) {
            console.error('Failed to reinitialize worker:', err);
            legacyFilterPacketsBySelectedFlows();
        }
    }
}

function syncWorkerWithRenderedData() {
    if (!workerManager || !mainGroup) return;
    
    // Get currently rendered dots data
    const dots = mainGroup.selectAll('.direction-dot');
    const renderedData = [];
    
    dots.each(function(d) {
        if (d) {
            // Extract the data bound to each DOM element
            renderedData.push({
                src_ip: d.src_ip,
                dst_ip: d.dst_ip,
                src_port: d.src_port,
                dst_port: d.dst_port,
                _packetIndex: renderedData.length // Use array index as packet index
            });
        }
    });
    
    if (renderedData.length > 0) {
        try {
            workerManager.initPackets(renderedData);
        } catch (err) {
            console.error('Failed to sync worker with rendered data:', err);
        }
    }
}
// state.data.full, state.data.filtered, state.data.isPreBinned moved to state.data (Phase 6)
let svg, mainGroup, width, height, xScale, yScale, zoom;
// Bottom overlay (fixed area above overview) for main x-axis and legends
let bottomOverlaySvg = null;
let bottomOverlayRoot = null;
let bottomOverlayAxisGroup = null;
let bottomOverlayDurationLabel = null;
let bottomOverlayWidth = 0;
let bottomOverlayHeight = 140; // generous to fit axis + legends without changing sizes
let chartMarginLeft = 150;
let chartMarginRight = 120;
// Layers for performance tuning: persistent full-domain layer and dynamic zoom layer
let fullDomainLayer = null;
let dynamicLayer = null;
// The element that has the zoom behavior attached (svg container)
let zoomTarget = null;
let dotsSelection; // Cache the dots selection for performance
        
// Overview timeline variables moved to overview_chart.js
let isHardResetInProgress = false; // Programmatic Reset View fast-path
// state.data.timeExtent moved to state.data (Phase 6)
// Global bin count is sourced from shared config.js
// pairs, state.layout.ipPositions, ipOrder moved to state.layout (Phase 4)

// TimeArcs integration variables moved to state.timearcs (Phase 3)

// Force layout variables moved to state.layout (Phase 4)
// Flow variables moved to state.flows (Phase 5)
// Global toggle state for invalid flow categories in legend
const hiddenInvalidReasons = new Set();
// Cache for IP filtered packet subsets (key: sorted IP list)
const filterCache = new Map();

// Cache for full-domain binned result to make Reset View fast (state.data.version moved to state.data)
let fullDomainBinsCache = { version: -1, data: [], binSize: null, sorted: false };
// Global radius scaling: anchor sizes across zooms
// - RADIUS_MIN: circle size for an individual packet (count = 1)
// - globalMaxBinCount: computed from the initial full-domain binning; reused at all zoom levels
let globalMaxBinCount = 1;

// useBinning and renderMode moved to state.ui (Phase 2)

// Consolidated state object for better organization
const state = {
    // Phase 1: Flow Detail Mode (isolated, ~20 refs)
    flowDetail: {
        mode: false,           // Whether we're in single-flow detail view
        flow: null,            // The flow object being viewed in detail
        packets: [],           // Extracted packets from the flow
        previousState: null    // State to restore when exiting flow detail mode
    },

    // Phase 2: UI Toggles (isolated, ~30 refs)
    ui: {
        showTcpFlows: true,      // Toggle for TCP flow visualization
        showEstablishment: true, // Toggle for establishment phase
        showDataTransfer: true,  // Toggle for data transfer phase
        showClosing: true,       // Toggle for closing phase
        showGroundTruth: false,  // Toggle for ground truth visualization
        useBinning: true,        // User toggle: binning on/off
        renderMode: 'circles'    // Render mode: 'circles' or 'bars'
    },

    // Phase 3: TimeArcs Integration (isolated, ~50 refs)
    timearcs: {
        ipOrder: null,            // Array of IPs in vertical order from TimeArcs, or null
        timeRange: null,          // {minUs, maxUs} or null (microseconds)
        overviewTimeExtent: null, // [start, end] in data units, or null (falls back to state.data.timeExtent)
        intendedZoomDomain: null  // [start, end] in data units, persists zoom state
    },

    // Phase 4: Layout (medium coupling, ~70 refs)
    layout: {
        ipPositions: new Map(),   // Global IP positions map
        ipOrder: [],              // Current vertical order of IPs
        pairs: new Map(),         // Global pairs map for IP pairing system
        forceLayout: null,        // Force layout object
        forceNodes: [],           // Force layout nodes
        forceLinks: [],           // Force layout links
        isForceLayoutRunning: false // Whether force layout is running
    },

    // Phase 5: Flows (medium coupling, ~60 refs)
    flows: {
        tcp: [],                  // Store detected TCP flows (from CSV)
        current: [],              // Flows matching current IP selection (subset of tcp)
        selectedIds: new Set(),   // Store IDs of selected flows as strings
        groundTruth: []           // Store ground truth events
    },

    // Phase 6: Data (high coupling, ~130 refs)
    data: {
        full: [],                 // Full dataset
        filtered: [],             // Filtered dataset (by IP selection)
        isPreBinned: false,       // Track if data is already pre-binned (from multi-resolution)
        version: 0,               // Increment when filtered data changes
        timeExtent: [0, 0]        // Global time extent for the dataset
    }
};

// Wrapper to call imported renderBars with required options
function renderBarsWithOptions(layer, binned) {
    renderBars(layer, binned, {
        xScale,
        flagColors,
        globalMaxBinCount,
        ROW_GAP,
        formatBytes,
        formatTimestamp,
        d3
    });
}

// Wrapper to call imported renderCircles with required options and event handlers
function renderCirclesWithOptions(layer, binned, rScale) {
    renderCircles(layer, binned, {
        xScale,
        rScale,
        flagColors,
        RADIUS_MIN,
        mainGroup,
        arcPathGenerator,
        findIPPosition,
        pairs: state.layout.pairs,
        ipPositions: state.layout.ipPositions,
        createTooltipHTML,
        FLAG_CURVATURE,
        d3
    });
}

// Unified render function - uses local wrappers that call imported modules
function renderMarksForLayerLocal(layer, data, rScale) {
    if (state.ui.renderMode === 'bars') return renderBarsWithOptions(layer, data);
    return renderCirclesWithOptions(layer, data, rScale);
}

// Draw a circle-size legend (bottom-right) for smallest/middle/largest counts
function drawSizeLegend(targetSvgOverride = null, targetWidth = null, targetHeight = null, axisY = null) {
    try {
        const targetSvg = targetSvgOverride || svg;
        const w = (typeof targetWidth === 'number') ? targetWidth : width;
        const h = (typeof targetHeight === 'number') ? targetHeight : height;
        if (!targetSvg || !w || !h) return;
        // Remove previous legend if any
        targetSvg.select('.size-legend').remove();

        const maxCount = Math.max(1, globalMaxBinCount);
        const midCount = Math.max(1, Math.round(maxCount / 2));
        const values = [1, midCount, maxCount];

        const rScale = d3.scaleSqrt().domain([1, maxCount]).range([RADIUS_MIN, RADIUS_MAX]);
        const radii = values.map(v => rScale(v));
        const maxR = Math.max(...radii, RADIUS_MIN);

        // Layout constants
        const padding = 8;
        const labelGap = 32; // top headroom for title + labels
        const legendWidth = maxR * 2 + padding * 2; // compact width
        const legendHeight = 2 * maxR + padding + (padding + labelGap); // space for title + labels

    const anchorY = (typeof axisY === 'number') ? axisY : h;
    const legendX = Math.max(0, w - legendWidth - 12);
    const legendY = Math.max(0, (anchorY - legendHeight - 8));

    const g = targetSvg.append('g')
        .attr('class', 'size-legend')
        .attr('transform', `translate(${legendX},${legendY})`)
        .style('pointer-events', 'none');

        // Background
        g.append('rect')
            .attr('x', 0)
            .attr('y', 0)
            .attr('rx', 6)
            .attr('ry', 6)
            .attr('width', legendWidth)
            .attr('height', legendHeight)
            .style('fill', '#fff')
            .style('opacity', 0.85)
            .style('stroke', '#ccc');

        // Title
        g.append('text')
            .attr('x', legendWidth / 2)
            .attr('y', padding + 10)
            .attr('text-anchor', 'middle')
            .style('font-size', '12px')
            .style('font-weight', '600')
            .style('fill', '#333')
            .text('Circle Size');

        // Baseline at the bottom inside the box
        const innerTop = padding + labelGap; // extra top room for labels
        const baseline = innerTop + 2 * maxR;
        const cx = padding + maxR; // center x for all circles

        // Draw nested circles (bottom-aligned), no fill. Draw largest first.
        const order = [2, 1, 0]; // indices for [max, mid, min]
        order.forEach((idx) => {
            const v = values[idx];
            const r = Math.max(RADIUS_MIN, radii[idx]);
            const cy = baseline - r; // bottom-aligned

            g.append('circle')
                .attr('cx', cx)
                .attr('cy', cy)
                .attr('r', r)
                .style('fill', 'none')
                .style('stroke', '#555');

            // Label centered above each circle
            g.append('text')
                .attr('x', cx)
                .attr('y', cy - r - 4)
                .attr('text-anchor', 'middle')
                .style('font-size', '12px')
                .style('fill', '#333')
                .text(v);
        });
    } catch (_) { /* ignore legend draw errors */ }
}

// Wrapper function for the extracted flag legend
function drawFlagLegend() {
    // Default to bottom overlay if available; fallback to main svg
    const targetSvg = bottomOverlayRoot || svg;
    const w = bottomOverlayRoot ? width : width;
    const h = bottomOverlayRoot ? bottomOverlayHeight : height;
    const axisBaseY = bottomOverlayRoot ? Math.max(20, bottomOverlayHeight - 20) : (height - 12);
    drawFlagLegendFromModule({ 
        svg: targetSvg, 
        width: w, 
        height: h, 
        flagColors, 
        globalMaxBinCount, 
        RADIUS_MIN, 
        RADIUS_MAX, 
        d3,
        axisY: axisBaseY
    });
}

// TCP flag colors, now loaded from flag_colors.json with defaults
let flagColors = { ...DEFAULT_FLAG_COLORS };
// Flow-related colors (closing types and invalid reasons) loaded from flow_colors.json
let flowColors = {
    closing: {
        graceful: '#8e44ad',
        abortive: '#c0392b'
    },
    ongoing: {
        open: '#6c757d',
        incomplete: '#adb5bd'
    },
    invalid: {
        // Optional overrides; default invalid reason colors derive from flagColors
    }
};

// Load color mapping for ground truth events
let eventColors = {};
fetch('color_mapping.json')
    .then(response => response.json())
    .then(colors => {
        eventColors = colors;
        LOG('Loaded event colors:', eventColors);
    })
    .catch(error => {
        console.warn('Could not load color_mapping.json:', error);
        // Use default colors if file not found
        eventColors = {
            'normal': '#4B4B4B',
            'client compromise': '#D41159',
            'malware ddos': '#2A9D4F',
            'scan /usr/bin/nmap': '#C9A200',
            'ddos': '#264D99'
        };
    });

// Load colors for flags from external JSON, merging into the existing object
fetch('flag_colors.json')
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
    .then(colors => {
        Object.assign(flagColors, colors);
        LOG('Loaded flag colors:', flagColors);
        try { drawFlagLegend(); } catch(e) { logCatchError('drawFlagLegend', e); }
    })
    .catch(err => {
        console.warn('Could not load flag_colors.json:', err);
        // keep defaults in flagColors
    });

// Load colors for flows (closing + invalid) from external JSON, deep-merge
fetch('flow_colors.json')
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
    .then(colors => {
        try {
            if (colors && typeof colors === 'object') {
                if (colors.closing && typeof colors.closing === 'object') {
                    flowColors.closing = { ...flowColors.closing, ...colors.closing };
                }
                if (colors.invalid && typeof colors.invalid === 'object') {
                    flowColors.invalid = { ...flowColors.invalid, ...colors.invalid };
                }
                if (colors.ongoing && typeof colors.ongoing === 'object') {
                    flowColors.ongoing = { ...flowColors.ongoing, ...colors.ongoing };
                }
            }
            LOG('Loaded flow colors:', flowColors);
        } catch (e) { console.warn('Merging flow_colors.json failed:', e); }
    })
    .catch(err => {
        console.warn('Could not load flow_colors.json:', err);
        // keep defaults in flowColors
    });

// Initialization function for the bar diagram module
function initializeBarVisualization() {
    // Initialize overview module with references
    initOverview({
        d3,
        applyZoomDomain: (domain, source) => applyZoomDomain(domain, source),
        getWidth: () => width,
        getTimeExtent: () => {
            const result = state.timearcs.overviewTimeExtent || flowDataState?.timeExtent || state.data.timeExtent;
            console.log('[getTimeExtent] Returning:', result, '| state.timearcs.overviewTimeExtent:', state.timearcs.overviewTimeExtent, '| flowDataState?.timeExtent:', flowDataState?.timeExtent, '| timeExtent:', state.data.timeExtent);
            return result;
        },
        getCurrentDomain: () => {
            // Return current xScale domain, with state.timearcs.intendedZoomDomain as fallback
            // This handles race conditions where zoom hasn't been applied yet
            const current = xScale ? xScale.domain() : null;
            if (current && current[0] !== undefined && current[1] !== undefined) {
                // Check if at full extent - if so, prefer state.timearcs.intendedZoomDomain
                const atFullExtent = state.data.timeExtent &&
                    Math.abs(current[0] - state.data.timeExtent[0]) < 1 &&
                    Math.abs(current[1] - state.data.timeExtent[1]) < 1;
                if (atFullExtent && state.timearcs.intendedZoomDomain) {
                    return state.timearcs.intendedZoomDomain;
                }
                return current;
            }
            return state.timearcs.intendedZoomDomain || current;
        },
        getOverviewTimeExtent: () => state.timearcs.overviewTimeExtent, // TimeArcs range or null
        getCurrentFlows: () => state.flows.current,
        getSelectedFlowIds: () => state.flows.selectedIds,
        updateTcpFlowPacketsGlobal: () => updateTcpFlowPacketsGlobal(),
        createFlowList: (flows) => createFlowList(flows),
        // Load flows for a given time range (async, prefers FlowListLoader CSV files when available)
        loadChunksForTimeRange: async (startTime, endTime) => {
            const state = getFlowDataState();

            // Get currently selected IPs to filter flows
            const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked'))
                .map(cb => cb.value);

            // Try FlowListLoader first (loads from CSV files - works without chunk files)
            const flowListLoader = getFlowListLoader();
            if (flowListLoader.isLoaded()) {
                console.log(`[loadChunksForTimeRange] Using FlowListLoader CSV for ${selectedIPs.length} IPs, time: ${startTime}-${endTime}`);
                const flows = await flowListLoader.filterByIPs(selectedIPs, [startTime, endTime]);
                console.log(`[loadChunksForTimeRange] FlowListLoader returned ${flows.length} flows`);
                return flows;
            }

            // Fall back to chunked flows loader
            if (state && typeof state.loadChunksForTimeRange === 'function') {
                return await state.loadChunksForTimeRange(startTime, endTime, selectedIPs);
            }
            if (state && typeof state.loadFlowsForTimeRange === 'function') {
                const result = await state.loadFlowsForTimeRange(startTime, endTime);
                // For multires, filter by selected IPs here since the function doesn't support it
                if (result && selectedIPs.length > 0) {
                    const selectedIPSet = new Set(selectedIPs);
                    return result.filter(f =>
                        selectedIPSet.has(f.initiator) && selectedIPSet.has(f.responder)
                    );
                }
                return result;
            }
            return [];
        },
        sbRenderInvalidLegend: (panel, html, title) => sbRenderInvalidLegend(panel, html, title),
        sbRenderClosingLegend: (panel, html, title) => sbRenderClosingLegend(panel, html, title),
        makeConnectionKey: (a,b,c,d) => makeConnectionKey(a,b,c,d),
        // Allow overview legend toggles to affect the arc graph immediately
        applyInvalidReasonFilter: () => applyInvalidReasonFilter(),
        hiddenInvalidReasons,
        hiddenCloseTypes,
        flagColors,
        flowColors
    });
    initSidebar({
        onResetView: () => {
            if (state.data.full.length > 0 && zoomTarget && zoom && state.data.timeExtent && state.data.timeExtent[1] > state.data.timeExtent[0]) {
                isHardResetInProgress = true;
                applyZoomDomain([state.data.timeExtent[0], state.data.timeExtent[1]], 'reset');
                if (state.ui.showTcpFlows && state.flows.selectedIds && state.flows.selectedIds.size > 0) {
                    try { setTimeout(() => redrawSelectedFlowsView(), 0); } catch(e) { logCatchError('redrawSelectedFlowsView', e); }
                }
            }
        }
    });
    // Delegate sidebar event wiring
    sbWireSidebarControls({
        onIpSearch: (term) => sbFilterIPList(term),
        onSelectAllIPs: () => { document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = true); updateIPFilter(); },
        onClearAllIPs: () => { document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = false); updateIPFilter(); },
        onToggleShowTcpFlows: (checked) => { state.ui.showTcpFlows = checked; updateTcpFlowPacketsGlobal(); drawSelectedFlowArcs(); try { applyInvalidReasonFilter(); } catch(e) { logCatchError('applyInvalidReasonFilter', e); } },
        onToggleEstablishment: (checked) => { state.ui.showEstablishment = checked; drawSelectedFlowArcs(); try { applyInvalidReasonFilter(); } catch(e) { logCatchError('applyInvalidReasonFilter', e); } },
        onToggleDataTransfer: (checked) => { state.ui.showDataTransfer = checked; drawSelectedFlowArcs(); try { applyInvalidReasonFilter(); } catch(e) { logCatchError('applyInvalidReasonFilter', e); } },
        onToggleClosing: (checked) => { state.ui.showClosing = checked; drawSelectedFlowArcs(); try { applyInvalidReasonFilter(); } catch(e) { logCatchError('applyInvalidReasonFilter', e); } },
        onToggleGroundTruth: (checked) => { state.ui.showGroundTruth = checked; const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')).map(cb => cb.value); drawGroundTruthBoxes(selectedIPs); },
        onToggleBinning: (checked) => { 
            state.ui.useBinning = checked; 
            isHardResetInProgress = true; 
            
            // Force immediate re-render of the visualization
            try {
                // Re-render the main visualization with current filtered data
                visualizeTimeArcs(state.data.filtered);
                
                // Update TCP flow packets and arcs
                updateTcpFlowPacketsGlobal();
                
                // Redraw selected flow arcs with new binning
                drawSelectedFlowArcs();
                
                // Apply any active filters
                applyInvalidReasonFilter();
                
                // Update legends to reflect new scaling
                setTimeout(() => {
                    try { 
                        try {
                            const axisBaseY = Math.max(20, bottomOverlayHeight - 20);
                            drawSizeLegend(bottomOverlayRoot, width, bottomOverlayHeight, axisBaseY);
                        } catch(e) { logCatchError('drawSizeLegend', e); }
                        drawFlagLegend();
                        const selIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')).map(cb => cb.value);
                        drawGroundTruthBoxes(selIPs);
                    } catch(e) { logCatchError('binningToggle.refresh', e); }
                }, 50);
            } catch (e) {
                console.warn('Error updating visualization after binning toggle:', e);
                // Fallback to original behavior
                applyZoomDomain(xScale.domain(), 'program');
            }
        },
        onToggleRenderMode: (mode) => {
            try {
                state.ui.renderMode = (mode === 'bars') ? 'bars' : 'circles';
                // Re-render marks in current domain using chosen mode
                isHardResetInProgress = true;
                visualizeTimeArcs(state.data.filtered);
                updateTcpFlowPacketsGlobal();
                drawSelectedFlowArcs();
                applyInvalidReasonFilter();
            } catch (e) { console.warn('Render mode toggle failed', e); }
        }
    });

    // Window resize handler for responsive visualization
    setupWindowResizeHandler();

    // Wire Flow List modal controls
    try {
        sbWireFlowListModalControls({
            onSelectAll: () => {
                document.querySelectorAll('#flowListModalList .flow-checkbox').forEach(cb => { if (!cb.checked) cb.click(); });
            },
            onClearAll: () => {
                document.querySelectorAll('#flowListModalList .flow-checkbox').forEach(cb => { if (cb.checked) cb.click(); });
            },
            onSearch: (term) => {
                const items = document.querySelectorAll('#flowListModalList .flow-item');
                const t = (term || '').toLowerCase();
                items.forEach(it => {
                    const text = (it.innerText || it.textContent || '').toLowerCase();
                    it.style.display = text.includes(t) ? '' : 'none';
                });
            }
        });
    } catch(e) { logCatchError('sbWireFlowListModalControls', e); }
}

// Window resize handler for responsive visualization
// Uses module for event handling, with custom onResize callback for app-specific logic
function setupWindowResizeHandler() {
    const handleResizeLogic = () => {
        try {
            // Only proceed if we have data and existing visualization
            if (!state.data.full || state.data.full.length === 0 || !svg || !xScale || !yScale) {
                return;
            }

            console.log('[Resize] Handling window resize, updating visualization dimensions');

            // Store old dimensions for comparison
            const oldWidth = width;
            const oldHeight = height;

            // IMPORTANT: Save the current TIME DOMAIN before resize
            // This is what we want to preserve, not the pixel-based transform
            const currentDomain = xScale.domain();
            console.log('[Resize] Preserving time domain across resize:', currentDomain);
            console.log('[Resize] Current timeExtent:', state.data.timeExtent);

            const container = d3.select("#chart-container").node();
            if (!container) return;

            // Calculate new dimensions
            const containerRect = container.getBoundingClientRect();
            const newWidth = Math.max(400, containerRect.width - chartMarginLeft - chartMarginRight);
            const newHeight = Math.max(300, containerRect.height - 100); // Leave space for controls

            // Update global dimensions
            width = newWidth;
            height = newHeight;

            console.log(`[Resize] Dimensions: ${oldWidth}x${oldHeight} -> ${width}x${height}`);

            // Resize main SVG
            svg.attr('width', width + chartMarginLeft + chartMarginRight)
               .attr('height', height + 100); // Extra space for bottom margin

            // Update scales with new width
            if (xScale && state.data.timeExtent) {
                xScale.range([0, width]);
            }
            
            // Update bottom overlay dimensions
            bottomOverlayWidth = Math.max(0, newWidth + chartMarginLeft + chartMarginRight);
            d3.select('#chart-bottom-overlay-svg')
                .attr('width', bottomOverlayWidth)
                .attr('height', bottomOverlayHeight);
            
            if (bottomOverlayRoot) {
                bottomOverlayRoot.attr('transform', `translate(${chartMarginLeft},0)`);
            }
            
            // Update main chart axis and legends
            if (bottomOverlayAxisGroup && xScale && state.data.timeExtent) {
                const axis = d3.axisBottom(xScale).tickFormat(createSmartTickFormatter(state.data.timeExtent));
                bottomOverlayAxisGroup.call(axis);
                
                // Redraw legends with new dimensions
                const axisBaseY = Math.max(20, bottomOverlayHeight - 20);
                if (bottomOverlayDurationLabel) {
                    bottomOverlayDurationLabel.attr('y', axisBaseY - 12);
                }
                
                try { 
                    drawSizeLegend(bottomOverlayRoot, newWidth, bottomOverlayHeight, axisBaseY); 
                } catch (e) { 
                    LOG('Error redrawing size legend:', e); 
                }
                
                try { 
                    drawFlagLegend(); 
                } catch (e) { 
                    LOG('Error redrawing flag legend:', e); 
                }
            }
            
            // Update zoom behavior with new dimensions
            if (zoom && zoomTarget) {
                zoom.extent([[0, 0], [width, height]])
                    .scaleExtent([1, Math.max(20, width / 50)]);

                // Clear ALL caches and circles to force complete fresh rendering
                fullDomainBinsCache = { version: -1, data: [], binSize: null, sorted: false };
                state.data.version++;
                dotsSelection = null;

                // Clear circles from both layers - they'll be re-rendered with new scale
                if (fullDomainLayer) {
                    fullDomainLayer.selectAll('.direction-dot').remove();
                    fullDomainLayer.selectAll('.bin-bar-segment').remove();
                    fullDomainLayer.selectAll('.bin-stack').remove();
                }
                if (dynamicLayer) {
                    dynamicLayer.selectAll('.direction-dot').remove();
                    dynamicLayer.selectAll('.bin-bar-segment').remove();
                    dynamicLayer.selectAll('.bin-stack').remove();
                }

                // Restore the SAME TIME DOMAIN after resize using the proper zoom function
                if (currentDomain && currentDomain[0] !== undefined && currentDomain[1] !== undefined) {
                    console.log(`[Resize] Restoring zoom domain: [${currentDomain[0]}, ${currentDomain[1]}]`);
                    console.log(`[Resize] Domain width: ${currentDomain[1] - currentDomain[0]}`);

                    // Use applyZoomDomain which properly calculates transform and triggers re-render
                    isHardResetInProgress = true;
                    applyZoomDomain(currentDomain, 'resize');

                    // Verify the domain was restored
                    setTimeout(() => {
                        console.log(`[Resize] After applyZoomDomain, xScale.domain():`, xScale.domain());
                    }, 100);
                } else {
                    console.log('[Resize] No domain to restore, resetting to full domain');
                    isHardResetInProgress = true;
                    applyZoomDomain(state.data.timeExtent, 'resize');
                }
            }
            
            // Recreate overview chart with new dimensions using proper refresh mechanism
            if (state.data.timeExtent && state.data.timeExtent.length === 2) {
                try {
                    // Get selected IPs to pass to the adaptive overview refresh
                    const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked'))
                        .map(cb => cb.value);

                    const effectiveOverviewExtent = state.timearcs.overviewTimeExtent || state.data.timeExtent;

                    // Use refreshAdaptiveOverview which handles adaptive loading properly
                    // This ensures the overview chart uses the same data source as after IP filtering
                    refreshAdaptiveOverview(selectedIPs, effectiveOverviewExtent)
                        .then(() => {
                            // Restore brush selection to current zoom domain if available
                            if (xScale && updateBrushFromZoom) {
                                updateBrushFromZoom();
                            }
                        })
                        .catch(e => {
                            LOG('Error recreating overview chart on resize:', e);
                        });
                } catch (e) {
                    LOG('Error recreating overview chart on resize:', e);
                }
            }
            
            // The zoom handler will take care of redrawing dots and arcs
            // Just need to update any additional elements that aren't handled by zoom
            
            // Update clip path with new dimensions
            if (svg) {
                svg.select('#clip rect')
                    .attr('width', width + 40) // DOT_RADIUS equivalent
                    .attr('height', height + 80); // 2 * DOT_RADIUS equivalent
            }
            
            // Update global domain for overview sync
            try {
                window.__arc_x_domain__ = xScale.domain();
            } catch(e) { logCatchError('setArcXDomain', e); }
            
            LOG('Window resize handling complete');
            
        } catch (e) {
            console.warn('Error during window resize:', e);
        }
    };
    
    // Use module's resize handler with our custom logic
    return setupWindowResizeHandlerFromModule({
        debounceMs: 150,
        onResize: handleResizeLogic
    });
}



// Global update functions that preserve zoom state
let flowUpdateTimeout = null;

// Centralized helper to apply a new time domain to the main chart (keeps brush/wheel/flow zoom in sync)
// Wrapper that calls the module function with current global state
function applyZoomDomain(newDomain, source = 'program') {
    // If the source is the brush, notify overview to avoid circular updates
    if (source === 'brush') { try { setBrushUpdating(true); } catch(e) { logCatchError('setBrushUpdating', e); } }

    // In flow detail mode, use the flow's time extent as the base for zoom calculations
    let effectiveTimeExtent = state.data.timeExtent;
    if (state.flowDetail.mode && state.flowDetail.packets.length > 0) {
        const flowTimeExtent = d3.extent(state.flowDetail.packets, d => d.timestamp);
        const padding = Math.max(50000, (flowTimeExtent[1] - flowTimeExtent[0]) * 0.1);
        effectiveTimeExtent = [flowTimeExtent[0] - padding, flowTimeExtent[1] + padding];
    }

    applyZoomDomainFromModule(newDomain, {
        zoom,
        zoomTarget,
        xScale,
        timeExtent: effectiveTimeExtent,
        width,
        d3
    }, source);

    if (source === 'brush') {
        // Release the flag after the event loop so zoomed() can run with the guard
        setTimeout(() => { try { setBrushUpdating(false); } catch(e) { logCatchError('setBrushUpdating', e); } }, 0);
    }
}

/**
 * Convert TimeArcs range (microseconds) to data units and update state.timearcs.overviewTimeExtent.
 * Call this early after state.data.timeExtent is known, before creating overview chart.
 */
function updateOverviewTimeExtentFromTimearcs() {
    if (!state.timearcs.timeRange || !state.data.timeExtent || state.data.timeExtent[0] === state.data.timeExtent[1]) {
        return;
    }

    let { minUs, maxUs } = state.timearcs.timeRange;

    // Safety check: if min === max (single point), expand to 60 seconds
    if (minUs === maxUs) {
        console.warn('[updateOverviewTimeExtentFromTimearcs] TimeArcs range is a single point, expanding to 60 seconds');
        maxUs = minUs + 60_000_000; // Add 60 seconds in microseconds
    }

    const extentMax = Math.max(state.data.timeExtent[0], state.data.timeExtent[1]);

    let zoomMin, zoomMax;

    if (extentMax > 1e14) {
        // Data is in microseconds
        zoomMin = minUs;
        zoomMax = maxUs;
    } else if (extentMax > 1e11) {
        // Data is in milliseconds
        zoomMin = minUs / 1000;
        zoomMax = maxUs / 1000;
    } else if (extentMax > 1e8) {
        // Data is in seconds
        zoomMin = minUs / 1_000_000;
        zoomMax = maxUs / 1_000_000;
    } else {
        // Data might be in minutes
        zoomMin = minUs / 60_000_000;
        zoomMax = maxUs / 60_000_000;
    }

    // Add small padding
    const selectedRange = zoomMax - zoomMin;
    const padding = selectedRange * 0.05;
    const paddedMin = zoomMin - padding;
    const paddedMax = zoomMax + padding;

    // Clamp to data extent
    const clampedMin = Math.max(state.data.timeExtent[0], paddedMin);
    const clampedMax = Math.min(state.data.timeExtent[1], paddedMax);

    if (clampedMin < clampedMax) {
        state.timearcs.overviewTimeExtent = [clampedMin, clampedMax];
        state.timearcs.intendedZoomDomain = [clampedMin, clampedMax];
        console.log('[updateOverviewTimeExtentFromTimearcs] Set state.timearcs.overviewTimeExtent:', state.timearcs.overviewTimeExtent);
    }
}

// Apply TimeArcs time range as initial zoom (if set)
// TimeArcs passes times in microseconds, but data may be in different resolutions
function applyTimearcsTimeRangeZoom() {
    console.log('[TimeArcs Zoom] Called with:', { timeRange: state.timearcs.timeRange, timeExtent: state.data.timeExtent, zoom: !!zoom, zoomTarget: !!zoomTarget, xScale: !!xScale });

    if (!state.timearcs.timeRange) {
        console.log('[TimeArcs Zoom] No state.timearcs.timeRange set, skipping');
        return;
    }
    if (!state.data.timeExtent || state.data.timeExtent[0] === state.data.timeExtent[1]) {
        console.log('[TimeArcs Zoom] Invalid state.data.timeExtent, skipping');
        return;
    }
    if (!zoom || !zoomTarget || !xScale) {
        console.warn('[TimeArcs Zoom] Zoom not initialized yet, retrying in 200ms');
        setTimeout(() => applyTimearcsTimeRangeZoom(), 200);
        return;
    }

    let { minUs, maxUs } = state.timearcs.timeRange;

    // Safety check: if min === max (single point), expand to 60 seconds
    if (minUs === maxUs) {
        console.warn('[TimeArcs Zoom] TimeArcs range is a single point, expanding to 60 seconds');
        maxUs = minUs + 60_000_000; // Add 60 seconds in microseconds
    }

    // Infer the data's timestamp unit by examining state.data.timeExtent magnitude
    // Unix epoch in different units (approx year 2020):
    // - Microseconds: ~1.6e15
    // - Milliseconds: ~1.6e12
    // - Seconds: ~1.6e9
    // - Minutes: ~2.6e7
    const extentMax = Math.max(state.data.timeExtent[0], state.data.timeExtent[1]);

    let zoomMin, zoomMax;
    let detectedUnit = 'unknown';

    if (extentMax > 1e14) {
        // Data is in microseconds - use directly
        zoomMin = minUs;
        zoomMax = maxUs;
        detectedUnit = 'microseconds';
    } else if (extentMax > 1e11) {
        // Data is in milliseconds - convert from microseconds
        zoomMin = minUs / 1000;
        zoomMax = maxUs / 1000;
        detectedUnit = 'milliseconds';
    } else if (extentMax > 1e8) {
        // Data is in seconds - convert from microseconds
        zoomMin = minUs / 1_000_000;
        zoomMax = maxUs / 1_000_000;
        detectedUnit = 'seconds';
    } else {
        // Data might be in minutes - convert from microseconds
        zoomMin = minUs / 60_000_000;
        zoomMax = maxUs / 60_000_000;
        detectedUnit = 'minutes';
    }

    console.log(`[TimeArcs Zoom] Detected data unit: ${detectedUnit}, extentMax: ${extentMax}`);
    console.log(`[TimeArcs Zoom] TimeArcs range (us): [${minUs}, ${maxUs}]`);
    console.log(`[TimeArcs Zoom] Converted range: [${zoomMin}, ${zoomMax}]`);
    console.log(`[TimeArcs Zoom] Data timeExtent: [${state.data.timeExtent[0]}, ${state.data.timeExtent[1]}]`);

    // Add small padding based on SELECTED range (not data range)
    const selectedRange = zoomMax - zoomMin;
    const padding = selectedRange * 0.05; // 5% of selected range
    const paddedMin = zoomMin - padding;
    const paddedMax = zoomMax + padding;

    // Clamp to data extent
    const clampedMin = Math.max(state.data.timeExtent[0], paddedMin);
    const clampedMax = Math.min(state.data.timeExtent[1], paddedMax);

    console.log(`[TimeArcs Zoom] Selected range: ${selectedRange}, padding: ${padding}`);
    console.log(`[TimeArcs Zoom] After padding & clamping: [${clampedMin}, ${clampedMax}]`);

    // Only apply if range is valid
    if (clampedMin < clampedMax) {
        console.log('[TimeArcs Zoom] Applying zoom domain:', [clampedMin, clampedMax]);
        // Store as intended zoom domain (persists across operations)
        state.timearcs.intendedZoomDomain = [clampedMin, clampedMax];
        // Store as overview extent (the range shown in overview bar chart)
        state.timearcs.overviewTimeExtent = [clampedMin, clampedMax];
        console.log('[TimeArcs Zoom] Set state.timearcs.overviewTimeExtent:', state.timearcs.overviewTimeExtent);
        applyZoomDomain([clampedMin, clampedMax], 'timearcs');
        // Verify the zoom was applied
        setTimeout(() => {
            if (xScale) {
                console.log('[TimeArcs Zoom] Verify - xScale domain after zoom:', xScale.domain());
            }
        }, 100);
    } else {
        console.warn('[TimeArcs Zoom] Invalid range after clamping, skipping zoom');
    }

    // NOTE: Don't clear state.timearcs.timeRange here - it's still needed by handleFlowDataLoaded()
    // when flow data loads after packet data. The state.timearcs.intendedZoomDomain persists the zoom state.
    // state.timearcs.timeRange = null;
}

function updateTcpFlowLinesGlobalDebounced() {
    // Clear any pending update
    if (flowUpdateTimeout) {
        clearTimeout(flowUpdateTimeout);
    }
    
    // Schedule a new update after a short delay
        flowUpdateTimeout = setTimeout(() => { 
        updateTcpFlowPacketsGlobal();
        flowUpdateTimeout = null;
    }, 100); // 100ms debounce
}

// Wrapper function that uses the module function with global state
function buildSelectedFlowKeySet() {
    return buildSelectedFlowKeySetFromModule(state.flows.tcp, state.flows.selectedIds);
}

function updateTcpFlowPacketsGlobal() {
    // Hide/show dots and draw lines based on current selection
    filterPacketsBySelectedFlows();
    // If no flows selected, ensure all dots are visible in both layers
    if (!state.ui.showTcpFlows || state.flows.selectedIds.size === 0) {
        if (fullDomainLayer) {
            fullDomainLayer.selectAll('.direction-dot').style('display', 'block').style('opacity', 0.5);
            fullDomainLayer.selectAll('.bin-bar-segment').style('display', 'block').style('opacity', 0.7);
        }
        // Clear any stale selection-only marks to prevent size scale misreads
        if (dynamicLayer) {
            dynamicLayer.selectAll('.direction-dot').remove();
            dynamicLayer.selectAll('.bin-bar-segment').remove();
        }
        // Restore full-domain layer by default when no selection
        if (fullDomainLayer) fullDomainLayer.style('display', null);
        if (dynamicLayer) dynamicLayer.style('display', 'none');
    }
    drawSelectedFlowArcs();

    // If a flow selection is active, recompute bins for the selection and render in dynamic layer
    if (state.ui.showTcpFlows && state.flows.selectedIds.size > 0) {
        try { redrawSelectedFlowsView(); } catch (e) { console.warn('Redraw for selected flows failed:', e); }
    }
    // Apply invalid-reason visibility on top of any selection
    try { applyInvalidReasonFilter(); } catch(e) { logCatchError('applyInvalidReasonFilter', e); }
}

// Track hidden close types (graceful, abortive) from closing legend
const hiddenCloseTypes = new Set();

// Hide/show dots, arcs, and overview bars based on invalid-reason and closing-type toggles
function applyInvalidReasonFilter() {
    // If SVG not ready, nothing to do
    if (!svg) return;

    // Helper: build a mapping from connection key -> invalid reason
    const reasonByKey = new Map();
    // Helper: build a mapping from connection key -> closeType ('graceful','abortive', etc.)
    const closeTypeByKey = new Map();
    if (Array.isArray(state.flows.tcp)) {
        for (const f of state.flows.tcp) {
            if (!f) continue;
            const key = f.key || makeConnectionKey(f.initiator, f.initiatorPort, f.responder, f.responderPort);
            if (!key) continue;
            let r = f.invalidReason;
            if (!r && (f.closeType === 'invalid' || f.state === 'invalid')) r = 'unknown_invalid';
            reasonByKey.set(key, r || null);
            // Closing-type visibility: exclude invalid flows from ongoing group
            // Map non-invalid, non-closed flows to 'open' (established) or 'incomplete'
            const isInvalid = !!r || f.closeType === 'invalid' || f.state === 'invalid';
            let ct = null;
            if (!isInvalid) {
                if (f.closeType === 'graceful' || f.closeType === 'abortive') {
                    ct = f.closeType;
                } else {
                    ct = (f.establishmentComplete === true || f.state === 'established' || f.state === 'data_transfer') ? 'open' : 'incomplete';
                }
            }
            closeTypeByKey.set(key, ct);
        }
    }

    const keyIsHidden = (key) => {
        const r = reasonByKey.get(key);
        if (r && hiddenInvalidReasons && hiddenInvalidReasons.has(r)) return true;
        // If we also hide by close type, check the flow close type
        if (hiddenCloseTypes && hiddenCloseTypes.size > 0 && key) {
            const ct = closeTypeByKey.get(key);
            if (ct && hiddenCloseTypes.has(ct)) return true;
        }
        return false;
    };

    const nothingHidden = (!hiddenInvalidReasons || hiddenInvalidReasons.size === 0) && (!hiddenCloseTypes || hiddenCloseTypes.size === 0);

    // Dots (both layers live under mainGroup)
    if (mainGroup && mainGroup.selectAll) {
        mainGroup.selectAll('.direction-dot').each(function(d) {
            let hide = false;
            if (!nothingHidden) {
                if (d && Array.isArray(d.originalPackets) && d.originalPackets.length) {
                    let allHidden = true;
                    const arr = d.originalPackets;
                    // Sample up to first 50 packets for performance
                    const len = Math.min(arr.length, 50);
                    for (let i = 0; i < len; i++) {
                        const p = arr[i];
                        const key = makeConnectionKey(p.src_ip, p.src_port || 0, p.dst_ip, p.dst_port || 0);
                        if (!keyIsHidden(key)) { allHidden = false; break; }
                    }
                    hide = allHidden;
                } else if (d) {
                    const key = makeConnectionKey(d.src_ip, d.src_port || 0, d.dst_ip, d.dst_port || 0);
                    hide = keyIsHidden(key);
                }
            }
            // Apply phase-based visibility regardless of legend toggles
            if (!hide) {
                if (d && Array.isArray(d.originalPackets) && d.originalPackets.length) {
                    let anyVisibleByPhase = false;
                    const arr = d.originalPackets;
                    const len = Math.min(arr.length, 50);
                    for (let i = 0; i < len; i++) {
                        const p = arr[i];
                        const ftype = getFlagType(p);
                        if (isFlagVisibleByPhase(ftype, { showEstablishment: state.ui.showEstablishment, showDataTransfer: state.ui.showDataTransfer, showClosing: state.ui.showClosing })) { anyVisibleByPhase = true; break; }
                    }
                    hide = !anyVisibleByPhase;
                } else if (d) {
                    const ftype = getFlagType(d);
                    hide = !isFlagVisibleByPhase(ftype, { showEstablishment: state.ui.showEstablishment, showDataTransfer: state.ui.showDataTransfer, showClosing: state.ui.showClosing });
                }
            }
            d3.select(this)
                .style('display', hide ? 'none' : null)
                .style('opacity', hide ? 0 : null);
        });
        // Also apply to stacked bar segments if present
        mainGroup.selectAll('.bin-bar-segment').each(function(w) {
            const d = w && w.datum ? w.datum : w; // our bars bind an object {datum}
            let hide = false;
            if (!nothingHidden) {
                if (d && Array.isArray(d.originalPackets) && d.originalPackets.length) {
                    let allHidden = true;
                    const arr = d.originalPackets;
                    const len = Math.min(arr.length, 50);
                    for (let i = 0; i < len; i++) {
                        const p = arr[i];
                        const key = makeConnectionKey(p.src_ip, p.src_port || 0, p.dst_ip, p.dst_port || 0);
                        if (!keyIsHidden(key)) { allHidden = false; break; }
                    }
                    hide = allHidden;
                }
            }
            if (!hide) {
                const ftype = d ? getFlagType(d) : 'OTHER';
                hide = !isFlagVisibleByPhase(ftype, { showEstablishment: state.ui.showEstablishment, showDataTransfer: state.ui.showDataTransfer, showClosing: state.ui.showClosing });
            }
            d3.select(this).style('display', hide ? 'none' : null).style('opacity', hide ? 0 : null);
        });
    }

    // Flow arcs (drawn only for selected flows)
    if (mainGroup && mainGroup.selectAll) {
        mainGroup.selectAll('.flow-arc').each(function(d) {
            let hide = false;
            if (!nothingHidden && d) {
                const key = makeConnectionKey(d.src_ip, d.src_port || 0, d.dst_ip, d.dst_port || 0);
                hide = keyIsHidden(key);
            }
            d3.select(this)
                .style('display', hide ? 'none' : null)
                .style('opacity', hide ? 0 : null);
        });
    }

    // Overview stacked histogram segments (invalid reasons)
    try { updateOverviewInvalidVisibility(); } catch(e) { logCatchError('updateOverviewInvalidVisibility', e); }

    // Update legend item styles to reflect toggled state
    const panel = document.getElementById('invalidLegendPanel');
    if (panel) {
        panel.querySelectorAll('.invalid-legend-item').forEach((el) => {
            const reason = el.getAttribute('data-reason');
            const disabled = !!(reason && hiddenInvalidReasons && hiddenInvalidReasons.has(reason));
            el.style.opacity = disabled ? '0.45' : '1';
        });
    }

    // Update closing and ongoing legend styles and hide specific closing lines
    const cpanel = document.getElementById('closingLegendPanel');
    if (cpanel) {
        cpanel.querySelectorAll('.closing-legend-item').forEach((el) => {
            const t = el.getAttribute('data-type');
            const disabled = !!(t && hiddenCloseTypes && hiddenCloseTypes.has(t));
            el.style.opacity = disabled ? '0.45' : '1';
        });
    }
    const opanel = document.getElementById('ongoingLegendPanel');
    if (opanel) {
        opanel.querySelectorAll('.closing-legend-item').forEach((el) => {
            const t = el.getAttribute('data-type');
            const disabled = !!(t && hiddenCloseTypes && hiddenCloseTypes.has(t));
            el.style.opacity = disabled ? '0.45' : '1';
        });
    }

    // Hide explicit closing line groups per type
    const closingGroup = svg.select('.closing-lines');
    if (closingGroup && !closingGroup.empty()) {
        closingGroup.selectAll('.closing-line').each(function(d){
            let hide = false;
            if (!nothingHidden && d) {
                // d.type is 'graceful_close' or 'half_close'
                if (hiddenCloseTypes && hiddenCloseTypes.size > 0) {
                    if (d.type === 'graceful_close' && hiddenCloseTypes.has('graceful')) hide = true;
                    if (d.type === 'half_close' && hiddenCloseTypes.has('abortive')) hide = true;
                }
            }
            d3.select(this).style('display', hide ? 'none' : null).style('opacity', hide ? 0 : null);
        });
    }
}

// Rebin and redraw dots specifically for currently selected flows at the current zoom domain
function redrawSelectedFlowsView() {
    if (!svg || !xScale || !dynamicLayer) return;
    // Hide cached full-domain dots; we will render fresh selection-only dots
    if (fullDomainLayer) fullDomainLayer.style('display', 'none');
    dynamicLayer.style('display', null);

    const selectedKeys = buildSelectedFlowKeySet();
    if (selectedKeys.size === 0) {
        // Nothing selected: clear dynamic layer; caller will restore full layer when appropriate
        dynamicLayer.selectAll('.direction-dot').remove();
        return;
    }

    // Compute visible packets in current domain, filtered by selected flow keys
    let visiblePackets = getVisiblePackets(state.data.filtered, xScale);
    visiblePackets = visiblePackets.filter(p => {
        if (!p || !p.src_ip || !p.dst_ip) return false;
        const key = makeConnectionKey(p.src_ip, p.src_port || 0, p.dst_ip, p.dst_port || 0);
        return selectedKeys.has(key);
    });

    if (!visiblePackets || visiblePackets.length === 0) {
        dynamicLayer.selectAll('.direction-dot').remove();
        return;
    }

    // Data is always pre-binned from multi-resolution system - just add y positions
    const binnedPackets = visiblePackets.map(d => ({
        ...d,
        yPos: findIPPosition(d.src_ip, d.src_ip, d.dst_ip, state.layout.pairs, state.layout.ipPositions),
        binCenter: d.bin_start ? (d.bin_start + (d.bin_end - d.bin_start) / 2) : d.timestamp,
        flagType: d.flagType || d.flag_type || 'OTHER',
        binned: d.binned !== false,
        count: d.count || 1,
        originalPackets: d.originalPackets || [d]
    }));
    const rScale = d3.scaleSqrt().domain([1, Math.max(1, globalMaxBinCount)]).range([RADIUS_MIN, RADIUS_MAX]);
    renderMarksForLayerLocal(dynamicLayer, binnedPackets, rScale);

    // Sync worker with updated dynamic layer data
    setTimeout(() => {
        try { syncWorkerWithRenderedData(); } catch(e) { logCatchError('syncWorkerWithRenderedData', e); }
    }, 80);
    // Re-apply legend-based filtering
    try { applyInvalidReasonFilter(); } catch(e) { logCatchError('applyInvalidReasonFilter', e); }
}

// Worker-enabled packet filtering (falls back to legacy if worker unavailable)
function filterPacketsBySelectedFlows() {
    if (!svg || !mainGroup) return;
    if (!workerManager) { 
        legacyFilterPacketsBySelectedFlows(); 
        return; 
    }
    
    // Check if we have a reasonable number of dots to match our data
    const dots = mainGroup.selectAll('.direction-dot').nodes();
    const currentMask = workerManager.getVisibilityMask();
    
    if (currentMask && dots.length !== currentMask.length) {
        // DOM has been updated, worker mask is stale - try to resync
        if (DEBUG) console.warn(`Worker mask stale (mask=${currentMask.length}, dots=${dots.length}), attempting resync`);
        syncWorkerWithRenderedData();
        
        // After resync, if still mismatched, fall back to legacy
        const newMask = workerManager.getVisibilityMask();
        if (newMask && dots.length !== newMask.length) {
            if (DEBUG) console.warn('Resync failed, using legacy filtering');
            legacyFilterPacketsBySelectedFlows();
            return;
        }
    }
    
    const showAll = !state.ui.showTcpFlows || state.flows.selectedIds.size === 0;
    const selectedKeys = showAll ? [] : Array.from(buildSelectedFlowKeySet());
    workerManager.filterByKeys(selectedKeys, showAll);
}

// Legacy in-main-thread filtering retained for fallback/debug
function legacyFilterPacketsBySelectedFlows() {
    if (!svg || !mainGroup) return;
    const allDots = mainGroup.selectAll('.direction-dot');
    if (!state.ui.showTcpFlows || state.flows.selectedIds.size === 0) {
        allDots.style('display', 'block').style('opacity', 0.5);
        // Bars as well
        try { mainGroup.selectAll('.bin-bar-segment').style('display','block').style('opacity', 0.7); } catch(e) { logCatchError('barSegmentStyle', e); }
        return;
    }
    const selectedKeys = buildSelectedFlowKeySet();
    const nodes = allDots.nodes();
    const BATCH = 2500;
    function processBatch(start) {
        const end = Math.min(start + BATCH, nodes.length);
        for (let i = start; i < end; i++) {
            const node = nodes[i];
            const d = node.__data__;
            let match = false;
            if (d && d.originalPackets && Array.isArray(d.originalPackets)) {
                const arr = d.originalPackets;
                const len = Math.min(arr.length, 50);
                for (let j = 0; j < len; j++) {
                    const p = arr[j];
                    const key = makeConnectionKey(p.src_ip, p.src_port, p.dst_ip, p.dst_port);
                    if (selectedKeys.has(key)) { match = true; break; }
                }
            } else if (d) {
                const key = makeConnectionKey(d.src_ip, d.src_port, d.dst_ip, d.dst_port);
                match = selectedKeys.has(key);
            }
            node.style.display = match ? 'block' : 'none';
            node.style.opacity = match ? 0.5 : 0.1;
        }
        if (end < nodes.length) {
            requestAnimationFrame(() => processBatch(end));
        }
    }
    requestAnimationFrame(() => processBatch(0));

    // Apply same logic for bar segments based on their bound datum
    const barNodes = mainGroup.selectAll('.bin-bar-segment').nodes();
    const BATCH2 = 2000;
    function processBars(start) {
        const end = Math.min(start + BATCH2, barNodes.length);
        for (let i = start; i < end; i++) {
            const node = barNodes[i];
            const w = node.__data__;
            const d = w && w.datum ? w.datum : w;
            let match = false;
            if (d && Array.isArray(d.originalPackets)) {
                const arr = d.originalPackets;
                const len = Math.min(arr.length, 50);
                for (let j = 0; j < len; j++) {
                    const p = arr[j];
                    const key = makeConnectionKey(p.src_ip, p.src_port, p.dst_ip, p.dst_port);
                    if (selectedKeys.has(key)) { match = true; break; }
                }
            }
            node.style.display = match ? 'block' : 'none';
            node.style.opacity = match ? 0.7 : 0.1;
        }
        if (end < barNodes.length) requestAnimationFrame(() => processBars(end));
    }
    requestAnimationFrame(() => processBars(0));
}

// Function to draw persistent lines for selected flows
function drawSelectedFlowArcs() {
    if (!svg || !mainGroup) return;

    // Clear previous persistent lines
    mainGroup.selectAll(".flow-arc").remove();

    // If TCP flows are off or nothing selected, don't draw persistent lines
    if (!state.ui.showTcpFlows || state.flows.selectedIds.size === 0 || !state.flows.tcp || state.flows.tcp.length === 0) {
        return;
    }

    // Build lookup of selected flow connection keys
    const selectedKeys = buildSelectedFlowKeySet();
    if (selectedKeys.size === 0) return;

    // Only draw lines for packets in the visible time range
    const [t0, t1] = xScale.domain();
    
    // Get visible packets for selected flows
    let visiblePackets = state.data.filtered.filter(p => {
        const ts = Math.floor(p.timestamp);
        if (ts < t0 || ts > t1) return false;
        const key = makeConnectionKey(p.src_ip, p.src_port, p.dst_ip, p.dst_port);
        return selectedKeys.has(key);
    });

    // Group packets by their pre-binned time bucket + src/dst pair + flagType
    // Data is always pre-binned, so use binCenter/binStart directly
    const arcGroups = new Map();
    for (const packet of visiblePackets) {
        // Use pre-binned time bucket (binCenter or binStart), not raw timestamp
        const timeBucket = packet.binCenter || packet.binStart || packet.bin_start || packet.timestamp;
        const flagType = packet.flagType || packet.flag_type || getFlagType(packet);
        const key = `${timeBucket}|${packet.src_ip}|${packet.src_port || 0}|${packet.dst_ip}|${packet.dst_port || 0}|${flagType}`;
        let g = arcGroups.get(key);
        if (!g) {
            g = {
                timestamp: timeBucket,
                src_ip: packet.src_ip,
                dst_ip: packet.dst_ip,
                src_port: packet.src_port || 0,
                dst_port: packet.dst_port || 0,
                flags: packet.flags,
                flagType,
                count: 0,
                originalPackets: [],
                rep: packet
            };
            arcGroups.set(key, g);
        }
        g.count += packet.count || 1;
        g.originalPackets.push(packet);
    }

    const groups = Array.from(arcGroups.values());

    // Build a bin-count map from the same binning used for dots, so widths match the circle legend
        const ARC_STROKE_WIDTH = 2;
        const countMap = new Map();
        groups.forEach(g => {
            const key = `${g.timestamp}_${g.src_ip}_${g.src_port}_${g.dst_ip}_${g.dst_port}_${getFlagType(g)}`;
            countMap.set(key, g.count);
        });

    // Build a global linear scale from 1 to globalMaxBinCount (matches circle legend)
    const MIN_THICKNESS = 0.5;
    const MAX_THICKNESS = 8;
    const thicknessScale = d3.scaleLinear()
        .domain([1, Math.max(1, globalMaxBinCount)])
        .range([MIN_THICKNESS, MAX_THICKNESS])
        .clamp(true);

    groups.forEach(g => {
        const ftype = getFlagType(g);
        if (!isFlagVisibleByPhase(ftype, { showEstablishment: state.ui.showEstablishment, showDataTransfer: state.ui.showDataTransfer, showClosing: state.ui.showClosing })) return;

        const pathPacket = g.rep;
        const path = arcPathGenerator(pathPacket, { xScale, ipPositions: state.layout.ipPositions, pairs: state.layout.pairs, findIPPosition, flagCurvature: FLAG_CURVATURE });
        if (path && pathPacket.src_ip !== pathPacket.dst_ip) {
            // Lookup bin count using the group's time bucket (g.timestamp) and the source row y position
            const yPos = findIPPosition(pathPacket.src_ip, pathPacket.src_ip, pathPacket.dst_ip, state.layout.pairs, state.layout.ipPositions);
                const thickness = ARC_STROKE_WIDTH;
            const arc = mainGroup.append("path")
                .attr("class", "flow-arc")
                .attr("d", path)
                .style("stroke", flagColors[ftype] || flagColors.OTHER)
                .style("stroke-width", `${thickness}px`)
                .style("opacity", 0.5)
                .datum(g);

            // Add interactivity: show packet info on hover
            arc.on('mouseover', (event, d) => {
                const tooltip = d3.select('#tooltip');
                tooltip.style('display', 'block').html(createTooltipHTML(d));
            }).on('mousemove', (event) => {
                const tooltip = d3.select('#tooltip');
                tooltip.style('left', `${event.pageX + 40}px`).style('top', `${event.pageY - 40}px`);
            }).on('mouseout', () => {
                d3.select('#tooltip').style('display', 'none');
            });
        }
    });
}





// Function to draw ground truth event boxes
function drawGroundTruthBoxes(selectedIPs) {
    if (!state.ui.showGroundTruth || !state.flows.groundTruth || state.flows.groundTruth.length === 0) {
        // Remove existing ground truth boxes if not showing
        mainGroup.selectAll('.ground-truth-box').remove();
        mainGroup.selectAll('.ground-truth-label').remove();
        return;
    }

    const matchingEvents = filterGroundTruthByIPs(state.flows.groundTruth, selectedIPs);
    if (matchingEvents.length === 0) {
        mainGroup.selectAll('.ground-truth-box').remove();
        mainGroup.selectAll('.ground-truth-label').remove();
        return;
    }

    // Create ground truth group if it doesn't exist
    let groundTruthGroup = mainGroup.select('.ground-truth-group');
    if (groundTruthGroup.empty()) {
        groundTruthGroup = mainGroup.append('g').attr('class', 'ground-truth-group');
    }

    // Prepare data for boxes using new module function
    const boxData = prepareGroundTruthBoxData(matchingEvents, {
        xScale,
        findIPPosition,
        pairs: state.layout.pairs,
        ipPositions: state.layout.ipPositions,
        eventColors
    });

    // Update boxes
    const boxes = groundTruthGroup.selectAll('.ground-truth-box')
        .data(boxData, d => `${d.event.source}-${d.event.destination}-${d.event.startTimeMicroseconds}-${d.ip}-${d.isSource ? 'src' : 'dst'}`);

    boxes.exit().remove();

    const newBoxes = boxes.enter()
        .append('rect')
        .attr('class', 'ground-truth-box')
        .attr('fill', d => d.color)
        .attr('stroke', d => d.color);

    function formatAdjStop(adjStop, wasExpanded) {
        let s = epochMicrosecondsToUTC(adjStop).replace(' UTC','');
        if (s.includes('.')) s = s.split('.')[0];
        if (wasExpanded) s += ' (+59s)';
        return s;
    }
    function showTooltip(event, d) {
        const tooltip = d3.select('#tooltip');
        const adjStop = d.adjustedStopMicroseconds || d.event.stopTimeMicroseconds;
        const adjStart = d.adjustedStartMicroseconds || d.event.startTimeMicroseconds;
        const durationSec = Math.round((adjStop - adjStart) / 1_000_000);
        const startStr = d.event.startTime;
        const expandedStopStr = formatAdjStop(adjStop, false);
        let tooltipContent = `
            <b>${d.event.eventType}</b><br>
            IP: ${d.ip} (${d.isSource ? 'Source' : 'Destination'})<br>
            From: ${d.event.source}<br>
            To: ${d.event.destination}<br>
            Start: ${startStr}<br>
        `;
        if (d.wasExpanded) {
            tooltipContent += `Original Stop: ${d.event.stopTime}<br>`;
            tooltipContent += `Estimated Stop (+59s): ${expandedStopStr}<br>`;
            tooltipContent += `Estimated Duration: ~${durationSec}s`;
        } else {
            tooltipContent += `Stop: ${d.event.stopTime}<br>`;
            tooltipContent += `Duration: ${durationSec}s`;
        }
        tooltip.style('display','block').html(tooltipContent);
    }
    function moveTooltip(e) { d3.select('#tooltip').style('left', `${e.pageX + 40}px`).style('top', `${e.pageY - 40}px`); }
    function hideTooltip() { d3.select('#tooltip').style('display','none'); }
    groundTruthGroup.selectAll('.ground-truth-box')
        .on('mouseover', showTooltip)
        .on('mousemove', moveTooltip)
        .on('mouseout', hideTooltip);

    // Update all boxes (existing and new)
    groundTruthGroup.selectAll('.ground-truth-box')
        .attr('x', d => d.x)
        .attr('y', d => d.y)
        .attr('width', d => d.width)
        .attr('height', d => d.height);

    // Add labels for events that are wide enough (only on source IP boxes to avoid duplication)
    const labels = groundTruthGroup.selectAll('.ground-truth-label')
        .data(boxData.filter(d => d.width > 50 && d.isSource), d => `${d.event.source}-${d.event.destination}-${d.event.startTimeMicroseconds}-label`);

    labels.exit().remove();

    const newLabels = labels.enter()
        .append('text')
        .attr('class', 'ground-truth-label')
        .attr('fill', '#2c3e50')
        .style('pointer-events', 'none');

    // Update all labels
    groundTruthGroup.selectAll('.ground-truth-label')
        .attr('x', d => d.x + d.width / 2)
        .attr('y', d => d.y + d.height / 2)
        .text(d => d.event.eventType.length > 20 ? 
            d.event.eventType.substring(0, 17) + '...' : 
            d.event.eventType);

    // Keep ground-truth boxes and labels above packet circles and arcs
    try { groundTruthGroup.raise(); } catch(e) { logCatchError('groundTruthGroup.raise', e); }
}

// IP selection event listeners
document.getElementById('selectAllIPs').addEventListener('click', async () => {
    document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = true);
    await updateIPFilter();
});
        
document.getElementById('clearAllIPs').addEventListener('click', async () => {
    document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = false);
    await updateIPFilter();
});

// IP search functionality
document.getElementById('ipSearch').addEventListener('input', (e) => {
    filterIPList(e.target.value);
});

let updateTimeout = null;

// IP Filter Controller - orchestrates IP filtering and visualization updates
// Uses lazy initialization to ensure all dependencies are available
let ipFilterController = null;

function getIPFilterController() {
    if (!ipFilterController) {
        ipFilterController = createIPFilterController({
            d3,
            getState: () => state,
            getFlowDataState: () => flowDataState,
            getAdaptiveOverviewLoader: () => adaptiveOverviewLoader,
            getFilterCache: () => filterCache,
            setMultiResSelectedIPs,
            eventColors,
            visualizeTimeArcs,
            drawFlagLegend,
            updateIPStats,
            applyTimearcsTimeRangeZoom,
            computeForceLayoutPositions,
            updateTcpFlowStats,
            refreshAdaptiveOverview,
            calculateGroundTruthStats,
            sbUpdateGroundTruthStatsUI,
            logCatchError
        });
    }
    return ipFilterController;
}

async function updateIPFilter() {
    return getIPFilterController().updateIPFilter();
}

// Delegated to sidebar.js
const createIPCheckboxes = (uniqueIPs) => sbCreateIPCheckboxes(uniqueIPs, async () => await updateIPFilter());

const updateFlagStats = (packets) => sbUpdateFlagStats(packets, getFlagType, flagColors);

const updateIPStats = (packets) => sbUpdateIPStats(packets, flagColors, formatBytes);

// Initialize and run force layout to position IPs
// Uses extracted module functions with local state management
function computeForceLayoutPositions(packets, selectedIPs, onComplete) {
    if (state.layout.isForceLayoutRunning) {
        LOG('Force layout already running, stopping previous layout');
        if (state.layout.forceLayout) state.layout.forceLayout.stop();
    }

    const simWidth = (typeof width !== 'undefined' && width > 0) ? width : 800;
    const simHeight = (typeof height !== 'undefined' && height > 0) ? height : 600;

    const { nodes, links } = buildForceLayoutData(packets, selectedIPs, { width: simWidth, height: simHeight });
    
    if (nodes.length === 0) {
        if (onComplete) onComplete();
        return;
    }

    state.layout.forceNodes = nodes;
    state.layout.forceLinks = links;
    
    console.log(`[Force Layout] Starting with ${nodes.length} nodes and ${links.length} links`);

    // Log link strengths for debugging
    if (links.length > 0) {
        const maxCount = Math.max(...links.map(l => l.count));
        const minCount = Math.min(...links.map(l => l.count));
        console.log(`[Force Layout] Link counts: min=${minCount}, max=${maxCount}`);
    }

    // Use module function but with local callback for state management
    state.layout.forceLayout = computeForceLayoutPositionsBase(packets, selectedIPs, {
        d3,
        width: simWidth,
        height: simHeight,
        onComplete: (result) => {
            console.log('[Force Layout] Simulation ended');
            state.layout.isForceLayoutRunning = false;
            
            // Apply positions from module result to global state
            if (result && result.ipOrder && result.ipPositions) {
                state.layout.ipOrder = result.ipOrder;
                result.ipPositions.forEach((pos, ip) => {
                    state.layout.ipPositions.set(ip, pos);
                });

                console.log('[Force Layout] Assigned screen positions:',
                    state.layout.ipOrder.map((ip, idx) => ({ ip, y: state.layout.ipPositions.get(ip) })));

                // Update the visualization to use new positions
                if (svg && mainGroup) {
                    try {
                        // Update node labels to new positions with smooth animation
                        svg.selectAll('.node')
                            .transition()
                            .duration(800)
                            .attr('transform', d => `translate(0,${state.layout.ipPositions.get(d)})`);
                    } catch (e) {
                        console.error('[Force Layout] Error updating positions:', e);
                    }
                }
            }
            
            if (onComplete) onComplete();
        }
    });

    state.layout.isForceLayoutRunning = true;
}

// TCP States (matching tcp_analysis.py) - now imported as TCP_STATES

// ---- Tunables - now imported as HANDSHAKE_TIMEOUT_MS, REORDER_WINDOW_PKTS, REORDER_WINDOW_MS

// ---- Minimal flag helpers - now imported from src/tcp/flags.js

// ---- Per-flow state --------------------------------------------------------
// HandshakeState type
// 'NEW' | 'SYN_SEEN' | 'SYNACK_SEEN' | 'ACK3_SEEN' | 'INVALID'

// InvalidReason type
// 'ack_without_handshake' | 'orphan_syn_timeout' | 'orphan_synack_timeout' | 'bad_seq_ack_numbers' | 'rst_during_handshake'

// FlowState interface
// { hs, established, syn, synAck, ack3, firstSeenTs, lastSeenTs, pending, pendingBytes, invalid, timers }

function getFlow(map, key, ts) {
    let f = map.get(key);
    if (!f) {
        f = {
            hs: 'NEW',
            established: false,
            firstSeenTs: ts,
            lastSeenTs: ts,
            pending: [],
            pendingBytes: 0,
            timers: {}
        };
        map.set(key, f);
    }
    return f;
}

function applyPacketToHandshake(flow, pkt, now) {
    flow.lastSeenTs = now;
    if (flow.hs === 'INVALID' || flow.established) return;
    if (has(pkt, 'rst') && (flow.hs !== 'ACK3_SEEN')) {
        flow.hs = 'INVALID';
        flow.invalid = { reason: 'rst_during_handshake', atTs: now };
        return;
    }
    const pushPending = () => {
        flow.pending.push(pkt);
        if (flow.pending.length > REORDER_WINDOW_PKTS) flow.pending.shift();
        const cutoff = now - REORDER_WINDOW_MS;
        while (flow.pending.length && flow.pending[0].ts < cutoff) flow.pending.shift();
    };
    if (flow.hs === 'NEW' && isACKonly(pkt)) {
        pushPending();
        const oldest = flow.pending[0]?.ts ?? now;
        if ((now - oldest) > REORDER_WINDOW_MS) {
            flow.hs = 'INVALID';
            flow.invalid = { reason: 'ack_without_handshake', atTs: now };
        }
        return;
    }
    if (isSYN(pkt)) {
        flow.syn = pkt;
        flow.hs = 'SYN_SEEN';
        flow.timers.synExpire = now + HANDSHAKE_TIMEOUT_MS;
        return;
    }
    if (isSYNACK(pkt)) {
        flow.synAck = pkt;
        if (flow.hs === 'SYN_SEEN') {
            flow.hs = 'SYNACK_SEEN';
            flow.timers.synAckExpire = now + HANDSHAKE_TIMEOUT_MS;
            return;
        }
        if (flow.hs === 'NEW') {
            pushPending();
            const oldest = flow.pending[0]?.ts ?? now;
            if ((now - oldest) > REORDER_WINDOW_MS) {
                flow.hs = 'INVALID';
                flow.invalid = { reason: 'orphan_synack_timeout', atTs: now };
            }
            return;
        }
    }
    if (has(pkt,'ack') && !has(pkt,'syn') && !has(pkt,'rst')) {
        if (flow.syn && flow.synAck) {
            const okAckToSynAckSeq   = (pkt.ackNum === (flow.synAck.seq + 1) >>> 0);
            const okAckFromSynToAck3 = (flow.synAck.ackNum === ((flow.syn.seq + 1) >>> 0));
            if (!okAckToSynAckSeq || !okAckFromSynToAck3) {
                flow.hs = 'INVALID';
                flow.invalid = { reason: 'bad_seq_ack_numbers', atTs: now };
                return;
            }
            flow.ack3 = pkt;
            flow.hs = 'ACK3_SEEN';
            flow.established = true;
            flow.timers = {};
            flow.pending = [];
            return;
        }
        if (flow.syn && !flow.synAck) {
            pushPending();
            if (flow.timers.synExpire && now > flow.timers.synExpire) {
                flow.hs = 'INVALID';
                flow.invalid = { reason: 'orphan_syn_timeout', atTs: now };
            }
            return;
        }
        if (flow.hs === 'NEW') {
            pushPending();
            const oldest = flow.pending[0]?.ts ?? now;
            if ((now - oldest) > REORDER_WINDOW_MS) {
                flow.hs = 'INVALID';
                flow.invalid = { reason: 'ack_without_handshake', atTs: now };
            }
            return;
        }
    }
    if (flow.hs === 'SYN_SEEN' && flow.timers.synExpire && now > flow.timers.synExpire) {
        flow.hs = 'INVALID';
        flow.invalid = { reason: 'orphan_syn_timeout', atTs: now };
        return;
    }
    if (flow.hs === 'SYNACK_SEEN' && flow.timers.synAckExpire && now > flow.timers.synAckExpire) {
        flow.hs = 'INVALID';
        flow.invalid = { reason: 'orphan_synack_timeout', atTs: now };
        return;
    }
}

function detectHandshakePatterns(packets) {
    const handshakes = [];
    const connectionMap = new Map();
    
    // Group packets by connection (src_ip:src_port -> dst_ip:dst_port)
    packets.forEach(packet => {
        if (packet.src_port && packet.dst_port) {
            const connectionKey = `${packet.src_ip}:${packet.src_port}-${packet.dst_ip}:${packet.dst_port}`;
            const reverseKey = `${packet.dst_ip}:${packet.dst_port}-${packet.src_ip}:${packet.src_port}`;
            
            // Use the lexicographically smaller key to ensure consistent ordering
            const key = connectionKey < reverseKey ? connectionKey : reverseKey;
            
            if (!connectionMap.has(key)) {
                connectionMap.set(key, []);
            }
            connectionMap.get(key).push(packet);
        }
    });
    
    // Analyze each connection for handshake patterns
    connectionMap.forEach((connectionPackets, connectionKey) => {
        // Sort packets by timestamp
        connectionPackets.sort((a, b) => a.timestamp - b.timestamp);

        // Look for SYN -> SYN+ACK -> ACK patterns
        const synPackets = connectionPackets.filter(p => getFlagType(p) === 'SYN');
        const synAckPackets = connectionPackets.filter(p => getFlagType(p) === 'SYN+ACK');
        const ackPackets = connectionPackets.filter(p => getFlagType(p) === 'ACK');
        
        // Try to match handshake sequences
        synPackets.forEach(synPacket => {
            // Find corresponding SYN+ACK packet
            const synAckPacket = synAckPackets.find(sa => 
                sa.timestamp > synPacket.timestamp &&
                sa.ack_num === synPacket.seq_num + 1 &&
                ((sa.src_ip === synPacket.dst_ip && sa.dst_ip === synPacket.src_ip) ||
                 (sa.src_ip === synPacket.src_ip && sa.dst_ip === synPacket.dst_ip))
            );
            
            if (synAckPacket) {
                // Find corresponding ACK packet
                const ackPacket = ackPackets.find(ack => 
                    ack.timestamp > synAckPacket.timestamp &&
                    ack.seq_num === synPacket.seq_num + 1 &&
                    ack.ack_num === synAckPacket.seq_num + 1 &&
                    ((ack.src_ip === synPacket.src_ip && ack.dst_ip === synPacket.dst_ip) ||
                     (ack.src_ip === synPacket.dst_ip && ack.dst_ip === synPacket.src_ip))
                );
                
                if (ackPacket) {
                    handshakes.push({
                        connectionKey: connectionKey,
                        syn: synPacket,
                        synAck: synAckPacket,
                        ack: ackPacket,
                        initiator: synPacket.src_ip,
                        responder: synPacket.dst_ip
                    });
                }
            }
        });
    });
    
    return handshakes;
}

function detectClosingPatterns(packets) {
    const closings = [];
    const connectionMap = new Map();
    const connectionStates = new Map(); // Track connection states like tcp_analysis.py
    
    // Group packets by connection (src_ip:src_port -> dst_ip:dst_port)
    packets.forEach(packet => {
        if (packet.src_port && packet.dst_port) {
            const connectionKey = `${packet.src_ip}:${packet.src_port}-${packet.dst_ip}:${packet.dst_port}`;
            const reverseKey = `${packet.dst_ip}:${packet.dst_port}-${packet.src_ip}:${packet.src_port}`;
            
            // Use the lexicographically smaller key to ensure consistent ordering
            const key = connectionKey < reverseKey ? connectionKey : reverseKey;
            
            if (!connectionMap.has(key)) {
                connectionMap.set(key, []);
                // Initialize connection state (matching tcp_analysis.py Conn structure)
                connectionStates.set(key, {
                    initiator: null,
                    responder: null,
                    isn_i: null,
                    isn_r: null,
                    state: TCP_STATES.S_NEW,
                    t_syn: null,
                    t_synack: null,
                    t_ack3: null,
                    t_close: null,
                    close_reason: null,
                    saw_syn_in_capture: false
                });
            }
            connectionMap.get(key).push(packet);
        }
    });
    
    // Process each connection with state machine (matching tcp_analysis.py logic)
    connectionMap.forEach((connectionPackets, connectionKey) => {
        // Sort packets by timestamp
        connectionPackets.sort((a, b) => a.timestamp - b.timestamp);
        
        let state = connectionStates.get(connectionKey);
        let fin1Packet = null, fin2Packet = null, finalAckPacket = null;
        
        // Process packets in order to build state machine
        for (const packet of connectionPackets) {
            const flags = packet.flags;
            const syn = (flags & 0x02) !== 0;
            const ackf = (flags & 0x10) !== 0;
            const fin = (flags & 0x01) !== 0;
            const rst = (flags & 0x04) !== 0;
            
            // SYN packet (handshake start)
            if (syn && !ackf && !rst) {
                if (state.initiator === null) {
                    state.initiator = [packet.src_ip, packet.src_port];
                    state.responder = [packet.dst_ip, packet.dst_port];
                    state.isn_i = packet.seq_num;
                    state.t_syn = packet.timestamp;
                    state.state = TCP_STATES.S_INIT;
                    state.saw_syn_in_capture = true;
                }
            }
            
            // SYN+ACK packet
            else if (syn && ackf && !rst && state.state === TCP_STATES.S_INIT) {
                if (packet.ack_num === state.isn_i + 1) {
                    state.isn_r = packet.seq_num;
                    state.t_synack = packet.timestamp;
                    state.state = TCP_STATES.S_SYN_RCVD;
                }
            }
            
            // Final ACK (handshake complete)
            else if (ackf && !syn && !fin && !rst && state.state === TCP_STATES.S_SYN_RCVD) {
                if (packet.ack_num === state.isn_r + 1) {
                    state.t_ack3 = packet.timestamp;
                    state.state = TCP_STATES.S_EST;
                }
            }
            
            // RST (abortive close)
            else if (rst && state.state >= TCP_STATES.S_EST) {
                state.t_close = packet.timestamp;
                state.close_reason = "rst";
                state.state = TCP_STATES.S_ABORTED;
                break; // Connection terminated
            }
            
            // FIN-based graceful close (matching tcp_analysis.py state machine)
            else if (fin && state.state >= TCP_STATES.S_EST) {
                if (state.state === TCP_STATES.S_EST) {
                    // First FIN received
                    state.state = TCP_STATES.S_FIN_1;
                    fin1Packet = packet;
                } else if (state.state === TCP_STATES.S_FIN_1) {
                    // Second FIN received (from other side)
                    state.state = TCP_STATES.S_FIN_2;
                    fin2Packet = packet;
                }
            }
            // Final ACK after second FIN (normal TCP close)
            else if (ackf && !fin && !syn && !rst && state.state === TCP_STATES.S_FIN_2) {
                state.state = TCP_STATES.S_CLOSED;
                state.t_close = packet.timestamp;
                state.close_reason = "fin";
                finalAckPacket = packet;
                break; // Connection terminated
            }
        }
        
        // If we have a complete closing sequence, add it to results
        if (state.state === TCP_STATES.S_CLOSED && state.close_reason === "fin" && fin1Packet && fin2Packet && finalAckPacket) {
            closings.push({
                connectionKey: connectionKey,
                type: 'graceful_close',
                fin1: fin1Packet,
                fin2: fin2Packet,
                ack: finalAckPacket,
                initiator: state.initiator[0],
                responder: state.responder[0],
                state: state
            });
        }
        // Handle half-close (only one FIN received before connection ends)
        else if (state.state === TCP_STATES.S_FIN_1 && fin1Packet) {
            // Look for ACK to the FIN
            const ackPacket = connectionPackets.find(p => 
                p.timestamp > fin1Packet.timestamp &&
                (p.flags & 0x10) !== 0 && // ACK flag
                p.ack_num === fin1Packet.seq_num + 1 &&
                ((p.src_ip === fin1Packet.dst_ip && p.dst_ip === fin1Packet.src_ip) ||
                 (p.src_ip === fin1Packet.src_ip && p.dst_ip === fin1Packet.dst_ip))
            );
            
            if (ackPacket) {
                closings.push({
                    connectionKey: connectionKey,
                    type: 'half_close',
                    fin1: fin1Packet,
                    ack: ackPacket,
                    initiator: state.initiator[0],
                    responder: state.responder[0],
                    state: state
                });
            }
        }
    });
    
    return closings;
}

function updateHandshakeStats(handshakes) {
    const container = document.getElementById('handshakeStats');
    if (handshakes.length === 0) {
        container.innerHTML = 'No handshakes detected';
        container.style.color = '#666';
    } else {
        container.innerHTML = `Found ${handshakes.length} handshake(s)`;
        container.style.color = '#27ae60';
        
        // Debug info
        LOG('Handshake patterns detected:', handshakes);
    }
}

function updateClosingStats(closings) {
    const container = document.getElementById('closingStats');
    if (closings.length === 0) {
        container.innerHTML = 'No closing patterns detected';
        container.style.color = '#666';
    } else {
        // Group by type
        const typeCounts = {};
        closings.forEach(closing => {
            typeCounts[closing.type] = (closing.typeCounts || 0) + 1;
        });
        
        let statsHTML = `<strong>Found ${closings.length} closing pattern(s)</strong><br>`;
        Object.entries(typeCounts).forEach(([type, count]) => {
            const typeLabel = type.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
            statsHTML += `${typeLabel}: ${count}<br>`;
        });
        
        container.innerHTML = statsHTML;
        container.style.color = '#27ae60';
    }
}

/**
 * Update the zoom level indicator UI
 */
function updateZoomIndicator(visibleRangeUs, resolution = null, dataPoints = 0) {
    const timeRangeEl = document.getElementById('zoomTimeRange');
    const resEl = document.getElementById('zoomResolution');
    if (!timeRangeEl) return;

    timeRangeEl.textContent = formatDuration(visibleRangeUs);

    if (resEl && resolution) {
        const resConfig = FETCH_RES_BY_NAME[resolution];
        const label = resConfig?.uiInfo?.label || resolution;
        resEl.textContent = `${label} · ${dataPoints.toLocaleString()} points`;
    } else if (resEl) {
        resEl.textContent = dataPoints > 0 ? `${dataPoints.toLocaleString()} points` : '';
    }
}

// Wrapper for exportFlowToCSV that provides the state.data.full and helpers
function exportFlowToCSV(flow) {
    return exportFlowToCSVFromModule(flow, state.data.full, { classifyFlags, formatTimestamp });
}

const createFlowList = (flows) => {
    // Determine if packet data is available
    // If using flow_list.json (summary mode), flows don't have phases/packet data
    const flowListLoader = getFlowListLoader();
    const usingFlowListSummary = flowListLoader.isLoaded() && flowDataState?.hasFlowList;

    // Check if any flow has phases data (indicates packet data is available)
    const flowsHavePacketData = flows.length > 0 && flows.some(f =>
        f.phases && (
            (f.phases.establishment && f.phases.establishment.length > 0) ||
            (f.phases.dataTransfer && f.phases.dataTransfer.length > 0) ||
            (f.phases.closing && f.phases.closing.length > 0)
        )
    );

    // Packet data available if flows have phases OR if we have CSV data
    const hasPacketData = flowsHavePacketData || (state.data.full && state.data.full.length > 0);

    return sbCreateFlowListCapped(flows, state.flows.selectedIds, formatBytes, formatTimestamp, exportFlowToCSV, zoomToFlow, updateTcpFlowPacketsGlobal, flowColors, enterFlowDetailMode, hasPacketData);
};

const updateTcpFlowStats = (flows) => sbUpdateTcpFlowStats(flows, state.flows.selectedIds, formatBytes);

/**
 * Refresh the overview chart using the adaptive multi-resolution loader if available.
 * Falls back to the standard refreshFlowOverview() if adaptive loader is not initialized.
 *
 * @param {string[]} selectedIPs - Array of selected IP addresses
 * @param {[number, number]} state.data.timeExtent - Optional time extent override [start, end] in microseconds
 */
async function refreshAdaptiveOverview(selectedIPs, timeExtent = null) {
    // Check if adaptive loader is available
    if (!adaptiveOverviewLoader) {
        console.log('[AdaptiveOverview] Loader not available, falling back to refreshFlowOverview');
        try { refreshFlowOverview(); } catch (e) { console.warn('[Overview] Refresh failed:', e); }
        return;
    }

    // Get selected IPs if not provided
    if (!selectedIPs || selectedIPs.length === 0) {
        selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked'))
            .map(cb => cb.value);
    }

    if (selectedIPs.length < 2) {
        console.log('[AdaptiveOverview] Need at least 2 IPs selected');
        // Still render an empty overview
        try { refreshFlowOverview(); } catch (e) { console.warn('[Overview] Refresh failed:', e); }
        return;
    }

    // Determine time extent
    const effectiveTimeExtent = timeExtent || state.timearcs.overviewTimeExtent || flowDataState?.timeExtent || adaptiveOverviewLoader.getTimeExtent();
    if (!effectiveTimeExtent) {
        console.warn('[AdaptiveOverview] No time extent available');
        try { refreshFlowOverview(); } catch (e) { console.warn('[Overview] Refresh failed:', e); }
        return;
    }

    const [timeStart, timeEnd] = effectiveTimeExtent;
    console.log(`[AdaptiveOverview] Refreshing with ${selectedIPs.length} IPs, time range: ${((timeEnd - timeStart) / 60_000_000).toFixed(1)} minutes`);

    try {
        // Get adaptive overview data
        const adaptiveData = await adaptiveOverviewLoader.getOverviewData(
            selectedIPs,
            timeStart,
            timeEnd,
            { targetBinCount: 100 }
        );

        console.log(`[AdaptiveOverview] Got ${adaptiveData.bins.length} bins at ${adaptiveData.resolution} resolution`);

        // Get chart dimensions
        const container = document.getElementById('chart-container');
        const containerWidth = container ? container.clientWidth : 800;
        const margins = { left: 150, right: 120, top: 80, bottom: 50 };
        const chartWidth = Math.max(100, containerWidth - margins.left - margins.right);

        // Render using the adaptive function
        createOverviewFromAdaptive(adaptiveData, {
            timeExtent: effectiveTimeExtent,
            width: chartWidth,
            margins
        });

        console.log(`[AdaptiveOverview] Rendered overview chart with ${adaptiveData.resolution} resolution`);
    } catch (err) {
        console.error('[AdaptiveOverview] Error:', err);
        // Fall back to standard refresh
        try { refreshFlowOverview(); } catch (e) { console.warn('[Overview] Refresh failed:', e); }
    }
}

function filterIPList(searchTerm) {
    const ipItems = document.querySelectorAll('.ip-item');
    ipItems.forEach(item => {
        const ip = item.dataset.ip;
        const matches = ip.toLowerCase().includes(searchTerm.toLowerCase());
        item.style.display = matches ? 'block' : 'none';
    });
}

// createTooltipHTML is now imported from './src/rendering/tooltip.js'

// Global function to find the correct Y position for an IP (single row per IP)
function findIPPosition(ip, _src_ip, _dst_ip, _pairs, ipPositions) {
    if (!ipPositions) return 0;
    return ipPositions.get(ip) || 0;
}

// Async CSV parsing with progress tracking
async function parseCSVAsync(csvText, onProgress) {
    const lines = csvText.split('\n').filter(line => line.trim().length > 0);
    if (lines.length < 2) return [];
    
    // Parse header line
    const headerLine = lines[0];
    const headers = [];
    let current = '';
    let inQuotes = false;
    
    for (let j = 0; j < headerLine.length; j++) {
        const char = headerLine[j];
        if (char === '"') {
            inQuotes = !inQuotes;
        } else if (char === ',' && !inQuotes) {
            headers.push(current.trim());
            current = '';
        } else {
            current += char;
        }
    }
    headers.push(current.trim());
    
    const packets = [];
    const totalLines = lines.length - 1; // Exclude header
    const BATCH_SIZE = 1000; // Process in batches for progress updates
    
    for (let i = 1; i < lines.length; i += BATCH_SIZE) {
        const endIndex = Math.min(i + BATCH_SIZE, lines.length);
        
        for (let lineIndex = i; lineIndex < endIndex; lineIndex++) {
            const line = lines[lineIndex];
            if (!line.trim()) continue;
            
            const values = [];
            current = '';
            inQuotes = false;
            
            for (let j = 0; j < line.length; j++) {
                const char = line[j];
                if (char === '"') {
                    inQuotes = !inQuotes;
                } else if (char === ',' && !inQuotes) {
                    values.push(current.trim());
                    current = '';
                } else {
                    current += char;
                }
            }
            values.push(current.trim());
            
            if (values.length >= headers.length) {
                const packet = {};
                for (let k = 0; k < headers.length; k++) {
                    const header = headers[k].toLowerCase().replace(/[^a-z0-9]/g, '_');
                    let value = values[k];
                    
                    // Type conversion
                    if (header.includes('time') || header.includes('timestamp')) {
                        value = parseFloat(value) || 0;
                    } else if (header.includes('length') || header.includes('size') || header.includes('port') || header.includes('seq') || header.includes('ack')) {
                        value = parseInt(value) || 0;
                    }
                    
                    packet[header] = value;
                }
                
                if (packet.src_ip && packet.dst_ip && packet.timestamp) {
                    packets.push(packet);
                }
            }
        }
        
        // Update progress
        if (onProgress) {
            const progress = (endIndex - 1) / totalLines;
            onProgress(progress, `Parsing CSV... ${(endIndex - 1).toLocaleString()}/${totalLines.toLocaleString()} lines`);
        }
        
        // Allow UI to update
        if (i % (BATCH_SIZE * 5) === 0) {
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }
    
    LOG(`Parsed ${packets.length} packets from ${lines.length - 1} CSV lines`);
    return packets;
}

// CSV parsing helper function
function parseCSV(csvText) {
    const lines = csvText.split('\n').filter(line => line.trim().length > 0);
    if (lines.length < 2) return [];
    
    // Parse header line
    const headerLine = lines[0];
    const headers = [];
    let current = '';
    let inQuotes = false;
    
    for (let j = 0; j < headerLine.length; j++) {
        const char = headerLine[j];
        if (char === '"') {
            inQuotes = !inQuotes;
        } else if (char === ',' && !inQuotes) {
            headers.push(current.trim().replace(/"/g, ''));
            current = '';
        } else {
            current += char;
        }
    }
    headers.push(current.trim().replace(/"/g, ''));
    
    LOG(`CSV has ${headers.length} columns:`, headers.slice(0, 10));
    
    const packets = [];
    
    // Parse data lines
    for (let i = 1; i < lines.length; i++) {
        const values = [];
        const line = lines[i];
        current = '';
        inQuotes = false;
        
        // Parse each field in the line
        for (let j = 0; j < line.length; j++) {
            const char = line[j];
            if (char === '"') {
                inQuotes = !inQuotes;
            } else if (char === ',' && !inQuotes) {
                values.push(current.trim().replace(/"/g, ''));
                current = '';
            } else {
                current += char;
            }
        }
        values.push(current.trim().replace(/"/g, ''));
        
        // Only process lines with enough values
        if (values.length >= headers.length - 5) { // Allow some tolerance for missing fields
            const packet = {};
            headers.forEach((header, index) => {
                const value = values[index] || '';
                
                // Convert numeric fields
                if (['timestamp', 'src_port', 'dst_port', 'flags', 'seq_num', 'ack_num', 'length', 
                     'flow_start_time', 'flow_end_time', 'flow_total_packets', 'flow_total_bytes',
                     'establishment_packets', 'data_transfer_packets', 'closing_packets',
                     'src_sent_packets', 'src_recv_packets', 'src_sent_bytes', 'src_recv_bytes',
                     'src_first_ts', 'src_last_ts', 'dst_sent_packets', 'dst_recv_packets',
                     'dst_sent_bytes', 'dst_recv_bytes', 'dst_first_ts', 'dst_last_ts'].includes(header)) {
                    packet[header] = parseFloat(value) || 0;
                } else if (['establishment_complete', 'data_transfer_started', 'closing_started'].includes(header)) {
                    packet[header] = value.toLowerCase() === 'true';
                } else {
                    packet[header] = value || '';
                }
            });
            
            packet.timestamp = Math.floor(packet.timestamp);
            if (packet.timestamp > 0 && packet.src_ip && packet.dst_ip) {
                packets.push(packet);
            }
        }
        if (i % 10000 === 0) {
            LOG(`Parsed ${i}/${lines.length} lines...`);
        }
    }
    
    LOG(`Successfully parsed ${packets.length} packets from ${lines.length - 1} CSV lines`);
    return packets;
}

function handleFileLoad(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    // Show CSV loading progress
    try { sbShowCsvProgress('Reading CSV file...', 0); } catch(e) { logCatchError('sbShowCsvProgress', e); }
    
    const reader = new FileReader();
    reader.onload = async e => {
        try {
            const csvText = e.target.result;
            
            // Update progress for parsing phase
            try { sbUpdateCsvProgress(0.1, 'Parsing CSV data...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }
            
            const packets = await parseCSVAsync(csvText, (progress, label) => {
                try { sbUpdateCsvProgress(0.1 + (progress * 0.4), label); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }
            });
            
            if (packets && packets.length > 0) {
                // Packets
                state.data.full = packets;
                state.data.filtered = [];

                // Process TCP flows with progress
                try { sbUpdateCsvProgress(0.5, 'Processing TCP flows...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }
                try { sbShowFlowProgress('Processing flows…', 0); } catch(e) { logCatchError('sbShowFlowProgress', e); }
                const flowsFromCSV = await reconstructFlowsFromCSVAsync(packets, (processed, total) => {
                    try {
                        const pct = total > 0 ? processed / total : 0;
                        sbUpdateFlowProgress(pct, `Processing flows… ${processed.toLocaleString()}/${total.toLocaleString()}`);
                        // Update CSV progress (flows processing is 50-90% of total)
                        sbUpdateCsvProgress(0.5 + (pct * 0.4), `Processing flows… ${processed.toLocaleString()}/${total.toLocaleString()}`);
                    } catch(e) { logCatchError('flowProgressUpdate', e); }
                });
                state.flows.tcp = flowsFromCSV;
                state.flows.current = []; // Initialize as empty - will be populated when IPs are selected
                state.flows.selectedIds.clear(); // Clear selected flow IDs
                // Don't populate flow list or stats until IPs are selected
                updateTcpFlowStats(state.flows.current); // Show initial message about selecting IPs

                // IPs - extract unique IPs from packet data
                try { sbUpdateCsvProgress(0.9, 'Extracting IP addresses...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }
                const uniqueIPs = Array.from(new Set(state.data.full.flatMap(p => [p.src_ip, p.dst_ip]))).filter(Boolean);
                createIPCheckboxes(uniqueIPs);

                // Apply pre-filter if opened from TimeArcs brush selection
                applyBrushSelectionPrefilter();

                // Wait for user selection
                document.getElementById('loadingMessage').textContent = 'Please select 2 or more IP addresses to view connections.';
                document.getElementById('loadingMessage').style.display = 'block';
                
                LOG(`Loaded ${packets.length} packets from CSV with ${uniqueIPs.length} unique IPs`);
                
                // Verify flow-packet connection
                verifyFlowPacketConnection(packets, flowsFromCSV);
                // Initialize web worker after packets parsed - will sync with rendered data later
                try {
                    try { sbUpdateCsvProgress(0.95, 'Initializing web worker...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }
                    if (!workerManager) {
                        initializeWorkerManager();
                    }
                    // Don't init packets here - will sync with rendered data after visualization is built
                } catch (err) {
                    console.error('Worker init failed', err);
                }
                
                // Complete loading
                try { sbUpdateCsvProgress(1.0, 'Loading complete!'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }
                try { sbHideFlowProgress(); } catch(e) { logCatchError('sbHideFlowProgress', e); }
                setTimeout(() => {
                    try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }
                }, 1000);
            } else {
                try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }
                alert('Invalid CSV format: No valid packet data found.');
            }
        } catch (error) { 
            try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }
            alert('Error parsing CSV file: ' + error.message); 
        }
    };
    reader.readAsText(file);
}

function highlight(selected) {
    const hasSelection = selected && (selected.ip || selected.flag);
    
    if (hasSelection && selected.ip) {
        // Simple IP-based highlighting
        svg.selectAll(".node-label")
            .classed("faded", d => d !== selected.ip)
            .classed("highlighted", d => d === selected.ip);
        
        mainGroup.selectAll(".direction-dot")
            .classed("faded", d => d.src_ip !== selected.ip && d.dst_ip !== selected.ip)
            .classed("highlighted", d => d.src_ip === selected.ip || d.dst_ip === selected.ip);
    } else if (hasSelection && selected.flag) {
        // Flag-based highlighting
        mainGroup.selectAll(".direction-dot")
            .classed("faded", d => getFlagType(d) !== selected.flag)
            .classed("highlighted", d => getFlagType(d) === selected.flag);
    } else {
        // No selection - reset all highlighting
        mainGroup.selectAll(".direction-dot")
            .classed("faded", false)
            .classed("highlighted", false);
        svg.selectAll(".node-label")
            .classed("faded", false)
            .classed("highlighted", false);
    }
    
    // Update flag stats highlighting
    document.querySelectorAll('#flagStats [data-flag]').forEach(item => {
        if (hasSelection && selected.flag) {
            if (item.dataset.flag === selected.flag) {
                item.style.backgroundColor = '#e9ecef';
                item.style.fontWeight = 'bold';
            } else {
                item.style.opacity = '0.3';
            }
        } else {
            item.style.backgroundColor = '';
            item.style.fontWeight = '';
            item.style.opacity = '';
        }
    });
}


function zoomToFlow(flow) {
    if (!flow || !svg || !zoom || !xScale || !state.data.timeExtent || !Array.isArray(state.data.full)) {
        console.warn('Cannot zoom to flow: missing required objects');
        return;
    }
    let minTs = Math.floor(typeof flow.startTime === 'number' ? flow.startTime : NaN);
    let maxTs = Math.floor(typeof flow.endTime === 'number' ? flow.endTime : NaN);
    if (!Number.isFinite(minTs) || !Number.isFinite(maxTs)) {
        console.warn('zoomToFlow: Could not determine packet time range for flow', flow);
        return;
    }
    const totalRange = state.data.timeExtent[1] - state.data.timeExtent[0];
    const minPaddingUs = 50000; // 0.05s minimum margin on each side
    const paddingPixels = 2; // desired pixel padding on each side (very tight)
    const paddingPercent = 0.005; // 0.5% of the flow duration on each side (very tight)
    const timePerPixel = totalRange / Math.max(1, width);
    const paddingFromPixels = Math.ceil(paddingPixels * timePerPixel);
    const flowDuration = Math.max(1, maxTs - minTs);
    const paddingFromPercent = Math.ceil(flowDuration * paddingPercent);
    const cappedPercentPadding = Math.min(paddingFromPercent, Math.ceil(flowDuration * 0.25));
    const padding = Math.max(minPaddingUs, Math.min(paddingFromPixels, cappedPercentPadding));
    let zoomStart = minTs - padding;
    let zoomEnd = maxTs + padding;
    zoomStart = Math.max(state.data.timeExtent[0], Math.floor(zoomStart));
    zoomEnd = Math.min(state.data.timeExtent[1], Math.ceil(zoomEnd));
    if (zoomEnd <= zoomStart) zoomEnd = zoomStart + 1;
    applyZoomDomain([zoomStart, zoomEnd], 'flow');
    if (typeof updateBrushFromZoom === 'function') {
        try { window.__arc_x_domain__ = xScale.domain(); updateBrushFromZoom(); } catch(e) { logCatchError('updateBrushFromZoom', e); }
    }
}

/**
 * Load flow detail via fetch API (used when File System API is not available)
 * @param {Object} flowSummary - Flow summary with id, startTime
 * @param {Object} state - flowDataState with basePath and chunksMeta
 * @returns {Promise<Object|null>} Flow object with phases or null
 */
async function loadFlowDetailViaFetch(flowSummary, state) {
    const { basePath, chunksMeta, format, getChunkPath } = state;
    const flowId = flowSummary.id;
    const flowStartTime = flowSummary.startTime;
    const { initiator, responder, initiatorPort, responderPort } = flowSummary;

    console.log(`[FlowDetail-Fetch] ========================================`);
    console.log(`[FlowDetail-Fetch] Loading flow ${flowId} via fetch`);
    console.log(`[FlowDetail-Fetch] flowStartTime: ${flowStartTime}`);
    console.log(`[FlowDetail-Fetch] basePath: ${basePath}`);
    console.log(`[FlowDetail-Fetch] format: ${format}`);
    console.log(`[FlowDetail-Fetch] chunksMeta count: ${chunksMeta ? chunksMeta.length : 'null'}`);
    console.log(`[FlowDetail-Fetch] Connection: ${initiator}:${initiatorPort} ↔ ${responder}:${responderPort}`);

    // Find ALL chunks that could contain this flow (by time range AND IPs)
    // Note: Flow IDs do NOT map to chunk indices - chunks are organized by time, not ID
    const candidateChunks = [];
    for (const chunk of chunksMeta) {
        // Check time range - flow startTime should be within chunk's time range
        if (chunk.start <= flowStartTime && flowStartTime <= chunk.end) {
            // Also check if chunk contains both initiator and responder IPs
            const chunkIPs = chunk.ips || [];
            const hasInitiator = chunkIPs.includes(initiator);
            const hasResponder = chunkIPs.includes(responder);

            if (hasInitiator && hasResponder) {
                candidateChunks.push(chunk);
            }
        }
    }

    console.log(`[FlowDetail-Fetch] Found ${candidateChunks.length} candidate chunks`);

    if (candidateChunks.length === 0) {
        console.error(`Unable to find chunk for flow ${flowId} (${initiator} ↔ ${responder} @ ${flowStartTime})`);
        return null;
    }

    // Search through all candidate chunks until we find the flow
    for (const chunk of candidateChunks) {
        try {
            // Construct chunk path based on format
            let chunkPath;
            if (getChunkPath) {
                chunkPath = getChunkPath(chunk);
            } else if (format === 'chunked_flows_by_ip_pair' && chunk.folder) {
                chunkPath = `${basePath}/flows/by_pair/${chunk.folder}/${chunk.file}`;
            } else {
                chunkPath = `${basePath}/flows/${chunk.file}`;
            }
            console.log(`[FlowDetail-Fetch] Searching chunk ${chunk.file} at ${chunkPath}...`);
            const response = await fetch(chunkPath);
            if (!response.ok) {
                console.warn(`[FlowDetail-Fetch] Failed to load ${chunkPath}: HTTP ${response.status}`);
                continue;
            }
            const flows = await response.json();

            // Try to find by ID first
            let flow = flows.find(f => f.id === flowId);

            // If not found by ID, try matching by connection tuple + startTime
            if (!flow) {
                flow = flows.find(f =>
                    f.initiator === initiator &&
                    f.responder === responder &&
                    f.initiatorPort === initiatorPort &&
                    f.responderPort === responderPort &&
                    Math.abs(f.startTime - flowStartTime) < 1000 // Within 1ms
                );
            }

            if (flow) {
                const packetCount = countFlowPacketsLocal(flow);
                console.log(`[FlowDetail-Fetch] ✅ Found flow ${flowId} in ${chunk.file} with ${packetCount} packets`);
                console.log(`[FlowDetail-Fetch] Flow has phases:`, flow.phases ? Object.keys(flow.phases) : 'none');
                console.log(`[FlowDetail-Fetch] ========================================`);
                return flow;
            }
            console.log(`[FlowDetail-Fetch] Flow not in ${chunkPath}, continuing search...`);
        } catch (err) {
            console.warn(`[FlowDetail-Fetch] Error searching ${chunkPath}:`, err);
            // Continue to next chunk
        }
    }

    // Flow not found in any candidate chunk
    console.error(`[FlowDetail-Fetch] ❌ Flow ${flowId} not found in any of ${candidateChunks.length} candidate chunks`);
    console.log(`[FlowDetail-Fetch] ========================================`);
    return null;
}

/**
 * Extract packets from a flow's phases into a flat array (local version)
 * @param {Object} flow - Flow object with phases
 * @returns {Array} Array of packet objects
 */
function extractPacketsFromFlowLocal(flow) {
    if (!flow || !flow.phases) return [];

    const packets = [];
    const phases = ['establishment', 'dataTransfer', 'closing'];

    for (const phaseName of phases) {
        const phasePackets = flow.phases[phaseName] || [];
        for (const entry of phasePackets) {
            if (entry.packet) {
                packets.push({
                    ...entry.packet,
                    phase: phaseName,
                    phaseStep: entry.phase || entry.description || phaseName
                });
            }
        }
    }

    // Sort by timestamp
    packets.sort((a, b) => a.timestamp - b.timestamp);

    console.log(`[FlowDetail] Extracted ${packets.length} packets from flow`);
    return packets;
}

/**
 * Count packets in a flow's phases (local version)
 */
function countFlowPacketsLocal(flow) {
    if (!flow || !flow.phases) return 0;
    const est = flow.phases.establishment?.length || 0;
    const data = flow.phases.dataTransfer?.length || 0;
    const close = flow.phases.closing?.length || 0;
    return est + data + close;
}

/**
 * Enter flow detail mode - show only packets from a single flow with permanent arcs
 * @param {Object} flowSummary - Flow summary object from flow list
 */
async function enterFlowDetailMode(flowSummary) {
    console.log('[FlowDetail] enterFlowDetailMode called');
    console.log('[FlowDetail] flowSummary:', flowSummary);

    if (!flowSummary) {
        console.warn('[FlowDetail] Cannot enter flow detail mode: no flow provided');
        return;
    }

    console.log('[FlowDetail] Entering flow detail mode for:', flowSummary.id);

    // Save current state for restoration
    state.flowDetail.previousState = {
        filteredData: state.data.filtered,
        xScaleDomain: xScale ? xScale.domain().slice() : null,
        selectedFlowIds: new Set(state.flows.selectedIds),
        showTcpFlows: state.ui.showTcpFlows
    };

    // Show loading indicator
    const loadingIndicator = showFlowDetailLoading(flowSummary);

    try {
        let fullFlow = null;

        // Try File System API first (folder_integration.js)
        if (typeof getChunkedFlowState === 'function') {
            const chunkedState = getChunkedFlowState();
            if (chunkedState && typeof loadFlowDetailWithPackets === 'function') {
                console.log('[FlowDetail] Using File System API to load flow detail');
                fullFlow = await loadFlowDetailWithPackets(flowSummary);
            }
        }

        // Fallback to fetch API using flowDataState
        if (!fullFlow && flowDataState && flowDataState.basePath && flowDataState.chunksMeta) {
            console.log('[FlowDetail] Using fetch API to load flow detail');
            fullFlow = await loadFlowDetailViaFetch(flowSummary, flowDataState);
        }

        if (!fullFlow) {
            console.error('[FlowDetail] Failed to load flow detail - no loader available');
            hideFlowDetailLoading(loadingIndicator);
            alert('Unable to load flow detail. Please ensure a flows folder is loaded.');
            return;
        }

        // Extract packets from phases (use local function if folder_integration not available)
        const packets = extractPacketsFromFlowLocal(fullFlow);
        if (!packets || packets.length === 0) {
            console.warn('[FlowDetail] No packets found in flow');
            hideFlowDetailLoading(loadingIndicator);
            return;
        }

        // Store flow detail state
        state.flowDetail.mode = true;
        state.flowDetail.flow = fullFlow;
        state.flowDetail.packets = packets;

        // Update the visualization with flow packets
        renderFlowDetailView(fullFlow, packets);

        // Show flow detail mode indicator
        showFlowDetailModeUI(fullFlow);

        hideFlowDetailLoading(loadingIndicator);
        console.log(`[FlowDetail] Now showing ${packets.length} packets for flow ${fullFlow.id}`);

    } catch (err) {
        console.error('[FlowDetail] Error entering flow detail mode:', err);
        hideFlowDetailLoading(loadingIndicator);
        state.flowDetail.mode = false;
        state.flowDetail.flow = null;
        state.flowDetail.packets = [];
    }
}

/**
 * Exit flow detail mode - restore packets folder view
 */
function exitFlowDetailMode() {
    if (!state.flowDetail.mode) return;

    console.log('[FlowDetail] Exiting flow detail mode');

    // Clear flow detail state
    state.flowDetail.mode = false;
    state.flowDetail.flow = null;
    state.flowDetail.packets = [];

    // Hide flow detail mode UI
    hideFlowDetailModeUI();

    // Restore previous state
    if (state.flowDetail.previousState) {
        state.data.filtered = state.flowDetail.previousState.filteredData;
        state.flows.selectedIds = state.flowDetail.previousState.selectedFlowIds;
        state.ui.showTcpFlows = state.flowDetail.previousState.showTcpFlows;

        // Restore zoom domain first
        if (state.flowDetail.previousState.xScaleDomain && xScale) {
            applyZoomDomain(state.flowDetail.previousState.xScaleDomain, 'restore');
        }

        // Check if we're in flow mode (folder-based data) or packet mode (CSV data)
        if (flowDataState && (flowDataState.format === 'chunked_flows' || flowDataState.format === 'chunked_flows_by_ip_pair')) {
            // Flow mode: call updateIPFilter to refresh the flow visualization
            // This will re-render the overview chart and flow bars
            console.log('[FlowDetail] Restoring flow mode visualization');
            updateIPFilter().catch(err => {
                console.error('[FlowDetail] Error restoring flow view:', err);
            });
        } else if (state.data.filtered && state.data.filtered.length > 0) {
            // Packet mode: re-render with restored packet data
            visualizeTimeArcs(state.data.filtered);
        }

        state.flowDetail.previousState = null;
    }

    console.log('[FlowDetail] Restored to normal view');
}

/**
 * Render the flow detail view with packets and permanent arcs
 */
function renderFlowDetailView(flow, packets) {
    if (!svg || !mainGroup || !xScale) return;

    // Get flow IPs
    const flowIPs = [flow.initiator, flow.responder].filter(Boolean);

    // Calculate time extent from packets with padding
    const pktTimeExtent = d3.extent(packets, d => d.timestamp);
    const duration = pktTimeExtent[1] - pktTimeExtent[0];
    const padding = Math.max(50000, duration * 0.1); // 10% padding or 50ms minimum
    const viewTimeExtent = [pktTimeExtent[0] - padding, pktTimeExtent[1] + padding];

    // Update xScale domain and sync zoom transform
    xScale.domain(viewTimeExtent);

    // Apply zoom domain to sync the zoom behavior with the new scale
    // This ensures brush interactions work correctly in flow detail mode
    applyZoomDomain(viewTimeExtent, 'flowdetail');

    // Update the brush position to show the flow's time range in the overview
    try { window.__arc_x_domain__ = viewTimeExtent; updateBrushFromZoom(); } catch(e) { logCatchError('updateBrushFromZoom', e); }

    // Clear existing visualization elements
    if (fullDomainLayer) fullDomainLayer.selectAll('*').remove();
    if (dynamicLayer) dynamicLayer.selectAll('*').remove();
    mainGroup.selectAll('.flow-arc').remove();
    mainGroup.selectAll('.flow-detail-arc').remove();

    // Ensure IPs are in state.layout.ipPositions
    flowIPs.forEach(ip => {
        if (!state.layout.ipPositions.has(ip)) {
            const currentMax = Math.max(...Array.from(state.layout.ipPositions.values()), 0);
            state.layout.ipPositions.set(ip, currentMax + ROW_GAP);
        }
    });

    // Prepare packets for rendering - add y positions and flag info
    const preparedPackets = packets.map((p, idx) => ({
        ...p,
        _packetIndex: idx,
        yPos: findIPPosition(p.src_ip, p.src_ip, p.dst_ip, state.layout.pairs, state.layout.ipPositions),
        flagType: p.flag_type || classifyFlags(p.flags) || 'OTHER',
        binned: false,
        count: 1,
        originalPackets: [p]
    }));

    // Render packets as dots (no binning in detail view)
    const rScale = d3.scaleSqrt().domain([1, 10]).range([RADIUS_MIN, RADIUS_MAX]);
    renderMarksForLayerLocal(dynamicLayer, preparedPackets, rScale);
    dynamicLayer.style('display', null);

    // Draw permanent sequential arcs connecting packets
    drawFlowDetailArcs(flow, preparedPackets);

    // Update x-axis
    if (bottomOverlayAxisGroup && state.data.timeExtent) {
        bottomOverlayAxisGroup.call(d3.axisBottom(xScale).tickFormat(createSmartTickFormatter(viewTimeExtent)));
    }

    // Update IP labels to show only relevant IPs
    updateIPLabelsForFlowDetail(flowIPs);
}

/**
 * Draw permanent lines connecting sequential packets in flow detail view
 */
function drawFlowDetailArcs(flow, packets) {
    if (!mainGroup || packets.length < 2) return;

    // Remove any existing flow detail lines
    mainGroup.selectAll('.flow-detail-arc').remove();
    mainGroup.selectAll('.flow-detail-arcs').remove();

    // Create line group
    const lineGroup = mainGroup.append('g')
        .attr('class', 'flow-detail-arcs')
        .attr('clip-path', 'url(#clip)');

    // Draw simple straight lines between consecutive packets
    for (let i = 0; i < packets.length - 1; i++) {
        const p1 = packets[i];
        const p2 = packets[i + 1];

        if (!p1 || !p2) continue;

        const x1 = xScale(p1.timestamp);
        const x2 = xScale(p2.timestamp);
        const y1 = state.layout.ipPositions.get(p1.src_ip) || p1.yPos;
        const y2 = state.layout.ipPositions.get(p2.src_ip) || p2.yPos;

        // Get color from flag type of the source packet
        const flagType = p1.flagType || 'OTHER';
        const color = flagColors[flagType] || flagColors['OTHER'] || '#999';

        // Draw simple straight line
        lineGroup.append('line')
            .attr('class', 'flow-detail-arc')
            .attr('x1', x1)
            .attr('y1', y1)
            .attr('x2', x2)
            .attr('y2', y2)
            .attr('stroke', color)
            .attr('stroke-width', 1.5)
            .attr('stroke-opacity', 0.6);
    }
}

/**
 * Re-render flow detail view when zooming (updates positions based on current xScale)
 */
function renderFlowDetailViewZoomed() {
    if (!state.flowDetail.mode || !state.flowDetail.flow || state.flowDetail.packets.length === 0) return;

    // Prepare packets with updated positions
    const preparedPackets = state.flowDetail.packets.map((p, idx) => ({
        ...p,
        _packetIndex: idx,
        yPos: state.layout.ipPositions.get(p.src_ip) || findIPPosition(p.src_ip, p.src_ip, p.dst_ip, state.layout.pairs, state.layout.ipPositions),
        flagType: p.flag_type || classifyFlags(p.flags) || 'OTHER',
        binned: false,
        count: 1,
        originalPackets: [p]
    }));

    // Update dot positions
    dynamicLayer.selectAll('.direction-dot')
        .attr('cx', d => xScale(d.timestamp));

    // Redraw lines with new positions
    drawFlowDetailArcs(state.flowDetail.flow, preparedPackets);
}

/**
 * Ensure SVG arrowhead marker is defined
 */
function ensureArrowheadMarker() {
    if (!svg) return;

    let defs = svg.select('defs');
    if (defs.empty()) {
        defs = svg.append('defs');
    }

    if (defs.select('#arrowhead').empty()) {
        defs.append('marker')
            .attr('id', 'arrowhead')
            .attr('viewBox', '0 -5 10 10')
            .attr('refX', 8)
            .attr('refY', 0)
            .attr('markerWidth', 6)
            .attr('markerHeight', 6)
            .attr('orient', 'auto')
            .append('path')
            .attr('d', 'M0,-5L10,0L0,5')
            .attr('fill', '#666');
    }
}

/**
 * Update IP labels for flow detail view (show only flow IPs)
 */
function updateIPLabelsForFlowDetail(flowIPs) {
    if (!svg) return;

    svg.selectAll('.ip-label')
        .style('opacity', function() {
            const ip = d3.select(this).text();
            return flowIPs.includes(ip) ? 1 : 0.3;
        })
        .style('font-weight', function() {
            const ip = d3.select(this).text();
            return flowIPs.includes(ip) ? 'bold' : 'normal';
        });
}

/**
 * Show flow detail loading indicator
 */
function showFlowDetailLoading(flow) {
    const existing = document.getElementById('flowDetailLoading');
    if (existing) existing.remove();

    const indicator = document.createElement('div');
    indicator.id = 'flowDetailLoading';
    indicator.style.cssText = 'position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: rgba(255,255,255,0.95); padding: 20px 30px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.2); z-index: 5000; text-align: center;';
    indicator.innerHTML = `
        <div style="font-size: 14px; color: #333; margin-bottom: 8px;">Loading flow detail...</div>
        <div style="font-size: 12px; color: #666;">${flow.id}</div>
    `;
    document.body.appendChild(indicator);
    return indicator;
}

/**
 * Hide flow detail loading indicator
 */
function hideFlowDetailLoading(indicator) {
    if (indicator && indicator.parentNode) {
        indicator.parentNode.removeChild(indicator);
    }
}

/**
 * Show flow detail mode UI indicator
 */
function showFlowDetailModeUI(flow) {
    const existing = document.getElementById('flowDetailModeIndicator');
    if (existing) existing.remove();

    const indicator = document.createElement('div');
    indicator.id = 'flowDetailModeIndicator';
    indicator.style.cssText = 'position: fixed; top: 10px; left: 50%; transform: translateX(-50%); background: #2196F3; color: white; padding: 8px 20px; border-radius: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.2); z-index: 4000; display: flex; align-items: center; gap: 12px; font-size: 13px;';
    indicator.innerHTML = `
        <span><strong>Flow Detail Mode:</strong> ${flow.initiator}:${flow.initiatorPort} → ${flow.responder}:${flow.responderPort}</span>
        <button id="exitFlowDetailBtn" style="background: white; color: #2196F3; border: none; padding: 4px 12px; border-radius: 12px; cursor: pointer; font-weight: bold;">Exit</button>
    `;
    document.body.appendChild(indicator);

    document.getElementById('exitFlowDetailBtn').addEventListener('click', exitFlowDetailMode);
}

/**
 * Hide flow detail mode UI indicator
 */
function hideFlowDetailModeUI() {
    const indicator = document.getElementById('flowDetailModeIndicator');
    if (indicator) indicator.remove();
}

/**
 * Check if currently in flow detail mode
 */
function isInFlowDetailMode() {
    return state.flowDetail.mode;
}

function visualizeTimeArcs(packets) {
    // 1. Reset & Validation
    d3.select("#chart").html("");
    document.getElementById('loadingMessage').style.display = 'none';
    isInitialResolutionLoad = true;

    if (!packets || packets.length === 0) {
        document.getElementById('loadingMessage').textContent = 'No data to visualize.';
        document.getElementById('loadingMessage').style.display = 'block';
        return;
    }

    // 2. Compute flag counts for sorting
    const flagCounts = {};
    packets.forEach(packet => {
        const flagType = getFlagType(packet);
        flagCounts[flagType] = (flagCounts[flagType] || 0) + 1;
    });

    // 3. Compute time extent with padding
    const packetTimeExtent = d3.extent(packets, d => d.timestamp);
    try {
        const span = Math.max(1, packetTimeExtent[1] - packetTimeExtent[0]);
        const pad = Math.max(1, Math.floor(span * 0.02));
        packetTimeExtent[0] = packetTimeExtent[0] - pad;
        packetTimeExtent[1] = packetTimeExtent[1] + pad;
    } catch(e) { logCatchError('packetTimeExtentPadding', e); }

    // 4. Update state time extent and sync with overview
    state.data.timeExtent = packetTimeExtent;
    updateOverviewTimeExtentFromTimearcs();

    if (state.timearcs.overviewTimeExtent && state.timearcs.overviewTimeExtent[0] < state.timearcs.overviewTimeExtent[1]) {
        state.data.timeExtent = state.timearcs.overviewTimeExtent.slice();
        console.log('[visualizeData] Using state.timearcs.overviewTimeExtent for main chart:', state.data.timeExtent);
    } else {
        state.data.timeExtent = packetTimeExtent;
    }

    fullDomainBinsCache = { version: state.data.version, data: [], binSize: null, sorted: false };

    // 5. Layout setup
    const margin = {top: 80, right: 120, bottom: 50, left: 150};
    width = d3.select("#chart-container").node().clientWidth - margin.left - margin.right;
    const DOT_RADIUS = 40;

    // 6. Compute IP positioning using extracted module
    state.layout.ipPositions.clear();
    const positioning = computeIPPositioning(packets, {
        state,
        rowGap: ROW_GAP,
        topPad: TOP_PAD,
        timearcsOrder: state.timearcs.ipOrder,
        dotRadius: DOT_RADIUS
    });

    // Apply positioning to state
    applyIPPositioningToState(state, positioning);
    const { yDomain, yRange, minY, maxY } = positioning;
    height = positioning.height;

    if (state.timearcs.ipOrder && state.timearcs.ipOrder.length > 0) {
        console.log('[IP Order] Using TimeArcs vertical order:', state.layout.ipOrder.length, 'IPs');
    }

    // 7. Create scales
    xScale = d3.scaleLinear().domain(state.data.timeExtent).range([0, width]);
    yScale = d3.scaleLinear().domain([minY, maxY]).range([minY, maxY]);

    // 8. Update zoom indicator
    const visibleRangeUs = state.data.timeExtent[1] - state.data.timeExtent[0];
    if (visibleRangeUs > 0) {
        const resolution = getResolutionForVisibleRange(visibleRangeUs);
        const dataCount = fetchResManager.singleFileData.get(resolution)?.length || state.data.full.length;
        updateZoomIndicator(visibleRangeUs, resolution, dataCount);
        console.log(`[visualizeData] Updated zoom indicator: range=${(visibleRangeUs/60_000_000).toFixed(1)} min, resolution=${resolution}`);
    }

    // 9. Create SVG structure using extracted module
    const svgResult = createSVGStructure({
        d3,
        containerId: '#chart',
        width,
        height,
        margin,
        dotRadius: DOT_RADIUS
    });
    const svgContainer = svgResult.svgContainer;
    svg = svgResult.svg;
    mainGroup = svgResult.mainGroup;
    fullDomainLayer = svgResult.fullDomainLayer;
    dynamicLayer = svgResult.dynamicLayer;

    // 10. Create bottom overlay using extracted module
    try {
        chartMarginLeft = margin.left;
        chartMarginRight = margin.right;
        const overlayResult = createBottomOverlay({
            d3,
            overlaySelector: '#chart-bottom-overlay-svg',
            width,
            chartMarginLeft,
            chartMarginRight,
            overlayHeight: bottomOverlayHeight,
            xScale,
            tickFormatter: createSmartTickFormatter(state.data.timeExtent)
        });
        bottomOverlaySvg = overlayResult.bottomOverlaySvg;
        bottomOverlayRoot = overlayResult.bottomOverlayRoot;
        bottomOverlayAxisGroup = overlayResult.bottomOverlayAxisGroup;
        bottomOverlayDurationLabel = overlayResult.bottomOverlayDurationLabel;
        bottomOverlayWidth = overlayResult.bottomOverlayWidth;
    } catch (e) { LOG('Overlay init failed', e); }

    // 11. Create duration label updater using extracted module
    const updateZoomDurationLabel = createDurationLabelUpdater({
        getXScale: () => xScale,
        bottomOverlayDurationLabel
    });

    // Initial label render
    try { updateZoomDurationLabel(); } catch(e) { logCatchError('updateZoomDurationLabel', e); }

    // 12. Build IP row labels using extracted module
    try {
        renderIPRowLabels({
            d3,
            svg,
            yDomain,
            ipPositions: state.layout.ipPositions,
            onHighlight: (data) => highlight(data),
            onClearHighlight: () => highlight(null)
        });
    } catch (e) { LOG('Failed to build IP labels', e); }

    // 13. Setup overview chart
    try { window.__arc_x_domain__ = xScale.domain(); } catch(e) { logCatchError('setArcXDomain', e); }
    const effectiveOverviewExtent = state.timearcs.overviewTimeExtent || state.data.timeExtent;
    createOverviewChart(packets, { timeExtent: effectiveOverviewExtent, width });

    LOG('SVG setup:', {
        containerWidth: width + margin.left + margin.right,
        containerHeight: height + margin.top + margin.bottom,
        chartWidth: width,
        chartHeight: height,
        margin: margin,
        xScaleDomain: state.data.timeExtent,
        yScaleDomain: yDomain,
        yScaleRange: yRange
    });

    // 14. Create zoom handler using extracted module
    const xAxis = d3.axisBottom(xScale).tickFormat(createSmartTickFormatter(state.data.timeExtent));

    const zoomed = createTimeArcsZoomHandler({
        d3,
        getXScale: () => xScale,
        getState: () => state,
        getTimeExtent: () => state.data.timeExtent,
        width,
        fullDomainLayer,
        dynamicLayer,
        mainGroup,
        bottomOverlayAxisGroup,
        bottomOverlayDurationLabel,
        getFullDomainBinsCache: () => fullDomainBinsCache,
        setFullDomainBinsCache: (cache) => { fullDomainBinsCache = cache; },
        getIsHardResetInProgress: () => isHardResetInProgress,
        setIsHardResetInProgress: (val) => { isHardResetInProgress = val; },
        xAxis,
        updateBrushFromZoom,
        updateZoomDurationLabel,
        updateZoomIndicator,
        getResolutionForVisibleRange,
        renderFlowDetailViewZoomed,
        drawSelectedFlowArcs,
        drawGroundTruthBoxes,
        createSmartTickFormatter,
        getVisiblePackets,
        buildSelectedFlowKeySet,
        makeConnectionKey,
        findIPPosition,
        getFlagType,
        renderMarksForLayer: renderMarksForLayerLocal,
        getGlobalMaxBinCount: () => globalMaxBinCount,
        getFlagCounts: () => flagCounts,
        getMultiResData,
        isMultiResAvailable,
        getUseMultiRes: () => useMultiRes,
        setCurrentResolutionLevel: (level) => { currentResolutionLevel = level; },
        logCatchError
    });

    // 15. Initialize zoom behavior
    zoom = createZoomBehavior({
        d3,
        scaleExtent: [1, 1e9],
        onZoom: zoomed
    });
    zoomTarget = svgContainer;
    zoomTarget.call(zoom);

    // 16. Enable drag-to-reorder for IP rows
    const dragBehavior = createDragReorderBehavior({
        d3,
        svg,
        ipOrder: state.layout.ipOrder,
        ipPositions: state.layout.ipPositions,
        onReorder: () => {
            try { fullDomainBinsCache = { version: -1, data: [], binSize: null, sorted: false }; } catch(e) { logCatchError('fullDomainBinsCache.reset', e); }
            try { isHardResetInProgress = true; applyZoomDomain(xScale.domain(), 'program'); } catch(e) { logCatchError('applyZoomDomain', e); }
            try { drawSelectedFlowArcs(); } catch(e) { logCatchError('drawSelectedFlowArcs', e); }
            try {
                if (state.ui.showGroundTruth) {
                    const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')).map(cb => cb.value);
                    drawGroundTruthBoxes(selectedIPs);
                }
            } catch(e) { logCatchError('drawGroundTruthBoxes', e); }
            try { updateZoomDurationLabel(); } catch(e) { logCatchError('updateZoomDurationLabel', e); }
        }
    });
    svg.selectAll('.node').call(dragBehavior).style('cursor', 'grab');

    // 17. Initial render using extracted module
    const initialVisibleRangeUs = xScale.domain()[1] - xScale.domain()[0];
    const initialResolution = getResolutionForVisibleRange(initialVisibleRangeUs);
    console.log('[visualizeTimeArcs] xScale domain:', xScale.domain(), 'visibleRange:', (initialVisibleRangeUs/60_000_000).toFixed(1), 'min', 'resolution:', initialResolution);

    const initialRenderData = prepareInitialRenderData({
        d3,
        packets,
        xScale,
        state,
        fetchResManager,
        getResolutionForVisibleRange,
        getVisiblePackets,
        buildSelectedFlowKeySet,
        makeConnectionKey,
        findIPPosition,
        getFlagType,
        flagCounts
    });

    globalMaxBinCount = initialRenderData.globalMaxBinCount;
    console.log('[visualizeTimeArcs] globalMaxBinCount set from', initialResolution, 'data:', globalMaxBinCount);

    fullDomainBinsCache = { version: state.data.version, data: initialRenderData.binnedPackets, binSize: null, sorted: true };

    console.log('[visualizeTimeArcs] Rendering', initialRenderData.binnedPackets.length, 'binned packets to fullDomainLayer');
    performInitialRender({
        d3,
        fullDomainLayer,
        dynamicLayer,
        binnedPackets: initialRenderData.binnedPackets,
        globalMaxBinCount,
        radiusMin: RADIUS_MIN,
        radiusMax: RADIUS_MAX,
        renderMarksForLayer: renderMarksForLayerLocal
    });
    console.log('[visualizeTimeArcs] fullDomainLayer display set to visible');

    // 18. Post-render setup
    updateTcpFlowPacketsGlobal();

    // Sync worker with rendered data after initial rendering
    try {
        setTimeout(() => syncWorkerWithRenderedData(), 100);
    } catch (err) {
        console.error('Failed to sync worker after initial render:', err);
    }

    // 19. Draw legends
    try { drawSizeLegend(bottomOverlayRoot, width, bottomOverlayHeight); } catch(e) { logCatchError('drawSizeLegend', e); }
    try { drawFlagLegend(); } catch(e) { logCatchError('drawFlagLegend', e); }

    // 20. Draw overlays
    const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked'))
        .map(cb => cb.value);
    drawGroundTruthBoxes(selectedIPs);
    drawSelectedFlowArcs();
    try { drawFlagLegend(); } catch(e) { logCatchError('drawFlagLegend', e); }

    // 21. Final overlay sizing
    try {
        resizeBottomOverlay({
            d3,
            overlaySelector: '#chart-bottom-overlay-svg',
            width,
            chartMarginLeft,
            chartMarginRight,
            overlayHeight: bottomOverlayHeight,
            bottomOverlayRoot,
            bottomOverlayAxisGroup,
            xScale,
            tickFormatter: createSmartTickFormatter(state.data.timeExtent)
        });
    } catch(e) { logCatchError('bottomOverlayResize', e); }
}

// Make resize handler available globally for testing and debugging
window.setupWindowResizeHandler = setupWindowResizeHandler;

// Test function to manually trigger resize (for debugging)
window.testResize = function() {
    console.log('Testing manual resize...');
    const event = new Event('resize');
    window.dispatchEvent(event);
};

// Make loadFromPath available globally for manual data loading
// Usage: window.loadFromPath() or window.loadFromPath('path/to/data')
window.loadFromPath = null;  // Will be set after function is defined

// Cleanup function to remove event listeners and clear state
function cleanup() {
    console.log('Cleaning up bar visualization...');
    
    // Clear timeouts and intervals
    if (typeof resizeTimeout !== 'undefined') {
        clearTimeout(resizeTimeout);
    }
    
    // Remove event listeners
    const dataFileInput = document.getElementById('dataFile');
    if (dataFileInput) {
        dataFileInput.removeEventListener('change', handleFileLoad);
    }
    
    // Clear chart content
    const chartContainer = document.getElementById('chart');
    if (chartContainer) {
        chartContainer.innerHTML = '';
    }
    
    // Clear overview
    const overviewContainer = document.getElementById('overview-chart');
    if (overviewContainer) {
        overviewContainer.innerHTML = '';
    }
    
    // Clear bottom overlay
    const bottomOverlay = document.getElementById('chart-bottom-overlay-svg');
    if (bottomOverlay) {
        bottomOverlay.innerHTML = '';
    }
    
    // Terminate worker if exists
    if (workerManager) {
        workerManager.terminate();
        workerManager = null;
    }
    
    // Reset global state
    state.data.full = [];
    state.data.filtered = [];
    state.flows.current = [];
    state.flows.selectedIds.clear();
    
    // Clear SVG references
    svg = null;
    mainGroup = null;
}

// Global variable to store brush selection data for filtering
let brushSelectionData = null;

// Global variable to store data path from TimeArcs selection (for auto-loading)
let brushSelectionDataPath = null;

// Check if page was opened from TimeArcs brush selection
function checkForBrushSelectionData() {
    console.log('[ip_bar_diagram] Checking for brush selection data...');
    console.log('[ip_bar_diagram] Current URL:', window.location.href);
    console.log('[ip_bar_diagram] Search params:', window.location.search);

    const urlParams = new URLSearchParams(window.location.search);

    if (!urlParams.has('fromSelection')) {
        console.log('[ip_bar_diagram] No fromSelection parameter found in URL');
        return false;
    }

    // Get the storage key from URL parameter (supports multiple selections)
    const storageKey = urlParams.get('fromSelection');
    console.log('[ip_bar_diagram] Page opened from TimeArcs brush selection, key:', storageKey);

    try {
        // Read from localStorage (sessionStorage doesn't work across tabs)
        const storedData = localStorage.getItem(storageKey);
        if (!storedData) {
            console.warn('[ip_bar_diagram] No brush selection data found in localStorage for key:', storageKey);
            // Also check sessionStorage as fallback for older data
            const sessionData = sessionStorage.getItem(storageKey);
            if (sessionData) {
                console.log('[ip_bar_diagram] Found data in sessionStorage (legacy)');
            }
            return false;
        }

        brushSelectionData = JSON.parse(storedData);
        console.log('[ip_bar_diagram] Loaded brush selection data:', brushSelectionData);

        // Clear localStorage to prevent reuse (data is one-time)
        localStorage.removeItem(storageKey);
        console.log('[ip_bar_diagram] Cleared localStorage key:', storageKey);

        // Store IPs for pre-selection when data loads
        if (brushSelectionData.selection && brushSelectionData.selection.ips) {
            // This will be used to pre-select IPs when data is loaded
            window.brushSelectionPrefilterIPs = brushSelectionData.selection.ips;
            console.log('Pre-filter IPs set:', window.brushSelectionPrefilterIPs.length);
        }

        // Store ordered IPs from TimeArcs (if available) for vertical ordering
        if (brushSelectionData.selection && brushSelectionData.selection.ipsInOrder) {
            state.timearcs.ipOrder = brushSelectionData.selection.ipsInOrder;
            console.log('TimeArcs IP order set:', state.timearcs.ipOrder.length, 'IPs in vertical order');
        }

        // Store time range from TimeArcs (in microseconds) for initial zoom
        if (brushSelectionData.selection && brushSelectionData.selection.timeRange) {
            const tr = brushSelectionData.selection.timeRange;
            if (tr.minUs !== undefined && tr.maxUs !== undefined) {
                state.timearcs.timeRange = { minUs: tr.minUs, maxUs: tr.maxUs };
                console.log('TimeArcs time range set:', state.timearcs.timeRange, '(microseconds)');
            }
        }

        // Store data path for auto-loading (if provided by TimeArcs)
        // Prefer detailViewDataPath (multi-resolution format), fall back to baseDataPath
        if (brushSelectionData.detailViewDataPath) {
            brushSelectionDataPath = brushSelectionData.detailViewDataPath;
            console.log('TimeArcs detail view data path set:', brushSelectionDataPath);
        } else if (brushSelectionData.baseDataPath && brushSelectionData.baseDataPath !== './') {
            brushSelectionDataPath = brushSelectionData.baseDataPath;
            console.log('TimeArcs base data path set:', brushSelectionDataPath);
        }

        return true;

    } catch (e) {
        console.error('Error parsing brush selection data:', e);
        return false;
    }
}

// Apply brush selection pre-filter to IP checkboxes
function applyBrushSelectionPrefilter() {
    const prefilterIPs = window.brushSelectionPrefilterIPs;
    if (!prefilterIPs || prefilterIPs.length === 0) {
        return;
    }

    console.log('Applying brush selection pre-filter for', prefilterIPs.length, 'IPs');

    const prefilterSet = new Set(prefilterIPs);
    const checkboxes = document.querySelectorAll('#ipCheckboxes input[type="checkbox"]');
    let matchedCount = 0;

    checkboxes.forEach(cb => {
        if (prefilterSet.has(cb.value)) {
            cb.checked = true;
            matchedCount++;
        }
    });

    console.log(`Pre-filter matched ${matchedCount} of ${prefilterIPs.length} IPs`);

    // Clear the pre-filter to prevent re-application
    window.brushSelectionPrefilterIPs = null;

    // Trigger IP filter update to render the visualization
    if (matchedCount >= 2) {
        // Use setTimeout to ensure DOM updates are complete
        setTimeout(async () => {
            await updateIPFilter();
        }, 100);
    }
}

// Initialize the module
function init() {
    console.log('Initializing bar visualization...');

    // Add file input listener
    const dataFileInput = document.getElementById('dataFile');
    if (dataFileInput) {
        dataFileInput.addEventListener('change', handleFileLoad);
    }

    // Add folder data listener
    document.addEventListener('folderDataLoaded', handleFolderDataLoaded);

    // Add flow data listener (supplements existing data, doesn't reset)
    document.addEventListener('flowDataLoaded', handleFlowDataLoaded);

    // Initialize the visualization
    initializeBarVisualization();

    // Check if opened from TimeArcs brush selection
    const hasSelectionData = checkForBrushSelectionData();

    // Load ground truth data in the background
    // Load ground truth data asynchronously
    loadGroundTruthData().then(data => {
        state.flows.groundTruth = data;

        // Update ground truth stats display
        const container = document.getElementById('groundTruthStats');
        if (data.length > 0) {
            container.innerHTML = `Loaded ${data.length} ground truth events<br>Select 2+ IPs to view matching events`;
            container.style.color = '#27ae60';
        } else {
            container.innerHTML = 'Ground truth data not loaded';
            container.style.color = '#e74c3c';
        }
    });

    // Determine the data path to load from
    // Priority: 1) TimeArcs selection data path, 2) Default path
    const dataPathToLoad = brushSelectionDataPath || DEFAULT_DATA_PATH;

    if (hasSelectionData && brushSelectionDataPath) {
        console.log('Auto-loading data from TimeArcs selection path:', brushSelectionDataPath);
    }

    // Auto-load data from the determined path
    loadFromPath(dataPathToLoad).then(() => {
        // After packet data loads successfully, also auto-load flow data
        console.log('[Init] Packet data loaded, now auto-loading flow data...');
        return loadFlowsFromPath(DEFAULT_FLOW_DATA_PATH);
    }).then(() => {
        console.log('[Init] Flow data also loaded successfully');
    }).catch(err => {
        console.warn(`Auto-load from path "${dataPathToLoad}" failed:`, err.message);

        // If TimeArcs path failed and it's different from default, try default as fallback
        if (dataPathToLoad !== DEFAULT_DATA_PATH) {
            console.log('Trying fallback to default data path...');
            loadFromPath(DEFAULT_DATA_PATH).then(() => {
                // Also try to load flow data
                return loadFlowsFromPath(DEFAULT_FLOW_DATA_PATH);
            }).catch(fallbackErr => {
                console.warn('Fallback to default path also failed:', fallbackErr.message);
                console.log('Please use the file picker or folder selector to load data.');
            });
        } else {
            // Packet load failed but try flow data anyway
            loadFlowsFromPath(DEFAULT_FLOW_DATA_PATH).catch(flowErr => {
                console.warn('Flow data auto-load also failed:', flowErr.message);
            });
            console.log('Please use the file picker or folder selector to load data.');
        }
    });
}

// Handle folder data loaded event
function handleFolderDataLoaded(event) {
    console.log('Folder data loaded event received:', event.detail);

    try {
        const { packets, flowsIndex, ipStats, flagStats, manifest, multiResolution, isPreBinned, uniqueIPs: preloadedUniqueIPs } = event.detail;

        // Check for multi-resolution support
        if (multiResolution?.available) {
            useMultiRes = true;
            console.log('Multi-resolution enabled:', multiResolution.info);
        } else {
            useMultiRes = false;
            console.log('Multi-resolution not available, using standard loading');
        }

        if (!packets || packets.length === 0) {
            console.error('No data in folder. Event detail:', event.detail);
            console.error('multiResolution:', multiResolution);
            console.error('isPreBinned:', isPreBinned);
            alert(`Error: No data found in folder.

Possible causes:
1. Multi-resolution seconds data failed to load (check console)
2. packets.csv is too large to load in browser
3. Folder structure doesn't match expected format

Check browser console (F12) for detailed error logs.`);
            return;
        }

        // Track if data is pre-binned (skip binning in render)
        // Check both isPreBinned and isAggregated (folder_integration uses isAggregated)
        state.data.isPreBinned = isPreBinned || event.detail.isAggregated;

        if (state.data.isPreBinned) {
            console.log(`Processing ${packets.length} pre-binned data points from folder (seconds resolution)...`);
            // Normalize pre-binned data: convert snake_case to camelCase for compatibility
            packets.forEach(p => {
                if (p.flag_type && !p.flagType) p.flagType = p.flag_type;
                if (p.bin_start !== undefined && p.binCenter === undefined) {
                    p.binCenter = p.bin_start + ((p.bin_end || p.bin_start) - p.bin_start) / 2;
                }
                if (p.binned === undefined) p.binned = true;
                if (p.count === undefined) p.count = 1;
            });
        } else {
            console.log(`Processing ${packets.length} packets from folder...`);
        }

        // Set data - for pre-binned data, this is seconds-resolution bins
        state.data.full = packets;
        state.data.filtered = [];

        // Also populate fetchResManager.singleFileData so resolution lookup works correctly
        // Check both isPreBinned and isAggregated (folder_integration uses isAggregated)
        const isPreBinnedData = isPreBinned || event.detail.isAggregated;
        if (packets.length > 0) {
            fetchResManager.singleFileData.set('seconds', packets);
            console.log(`[FolderData] Stored ${packets.length} seconds bins in fetchResManager.singleFileData`);
        }

        // Convert flows index to flow objects (simplified format for now)
        state.flows.tcp = flowsIndex.map(flowSummary => ({
            id: flowSummary.id,
            key: flowSummary.key,
            initiator: flowSummary.initiator,
            responder: flowSummary.responder,
            initiatorPort: flowSummary.initiatorPort,
            responderPort: flowSummary.responderPort,
            state: flowSummary.state,
            closeType: flowSummary.closeType,
            startTime: flowSummary.startTime,
            endTime: flowSummary.endTime,
            totalPackets: flowSummary.totalPackets,
            totalBytes: flowSummary.totalBytes,
            establishmentComplete: flowSummary.establishmentComplete,
            dataTransferStarted: flowSummary.dataTransferStarted,
            closingStarted: flowSummary.closingStarted,
            invalidReason: flowSummary.invalidReason,
            ongoing: flowSummary.ongoing,
            phases: {
                establishment: Array(flowSummary.establishment_packets || 0).fill({}),
                dataTransfer: Array(flowSummary.data_transfer_packets || 0).fill({}),
                closing: Array(flowSummary.closing_packets || 0).fill({})
            }
        }));
        
        console.log(`Loaded ${state.flows.tcp.length} flows from folder`);
        
        // Initialize state.flows.current as empty - will be populated when IPs are selected
        state.flows.current = [];
        state.flows.selectedIds.clear();
        
        // Update TCP flow stats to show initial message
        updateTcpFlowStats(state.flows.current);

        // Get unique IPs - prefer pre-loaded list, fallback to extracting from data
        let uniqueIPs;
        if (preloadedUniqueIPs && preloadedUniqueIPs.length > 0) {
            uniqueIPs = preloadedUniqueIPs;
            console.log(`Using ${uniqueIPs.length} pre-loaded unique IPs`);
        } else {
            uniqueIPs = Array.from(new Set(state.data.full.flatMap(p => [p.src_ip, p.dst_ip]))).filter(Boolean);
            console.log(`Extracted ${uniqueIPs.length} unique IPs from data`);
        }
        createIPCheckboxes(uniqueIPs);

        // Initialize web worker for packet filtering
        try {
            if (!workerManager) {
                initializeWorkerManager();
            }
            // Will sync with rendered data after visualization is built
        } catch (err) {
            console.error('Worker init failed', err);
        }

        // Show message asking user to select IPs
        document.getElementById('loadingMessage').textContent = 'Please select 2 or more IP addresses to view connections.';
        document.getElementById('loadingMessage').style.display = 'block';
        
        console.log(`Folder data ready with ${packets.length} ${isPreBinned ? 'pre-binned data points' : 'packets'} and ${uniqueIPs.length} unique IPs`);

        // Show initial zoom indicator with full data range
        if (state.data.timeExtent && state.data.timeExtent.length === 2) {
            const fullRangeUs = state.data.timeExtent[1] - state.data.timeExtent[0];
            updateZoomIndicator(fullRangeUs, isPreBinned ? 'seconds' : null, packets.length);
        }

        // Hide progress
        try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }
        
    } catch (err) {
        console.error('Error handling folder data:', err);
        alert(`Error processing folder data: ${err.message}`);
        try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }
    }
}

// Store for flow data (separate from packet data)
let flowDataState = null;

// Adaptive overview loader for multi-resolution flow bins
let adaptiveOverviewLoader = null;

/**
 * Handle flow data loaded event
 * This supplements existing packet data without resetting the visualization
 * Preserves current IP selection and packet data
 */
async function handleFlowDataLoaded(event) {
    console.log('Flow data loaded event received:', event.detail);

    try {
        const detail = event.detail;
        const { manifest, totalFlows, timeExtent: flowTimeExtent, format } = detail;

        // Compute TimeArcs range if available (converts selection to match flow data units)
        computeTimeArcsRange({
            timeRange: state.timearcs.timeRange,
            flowTimeExtent,
            stateTimearcs: state.timearcs
        });

        // Dispatch to format-specific handler
        if ((format === 'chunked_flows' || format === 'chunked_flows_by_ip_pair') && detail.chunksMeta) {
            await handleChunkedFlowsFormat(detail, manifest, totalFlows, flowTimeExtent, format);
        } else if (format === 'chunked_flows' && detail.flows) {
            handleLegacyFlowsFormat(detail, manifest, flowTimeExtent);
        } else {
            handleMultiresFlowsFormat(detail, manifest, totalFlows, flowTimeExtent);
        }

    } catch (err) {
        console.error('Error handling flow data:', err);
        alert(`Error processing flow data: ${err.message}`);
    }
}

/**
 * Handle chunked flows format (v2/v3) with chunk metadata
 * @param {Object} detail - Event detail object
 * @param {Object} manifest - Data manifest
 * @param {number} totalFlows - Total flow count
 * @param {Array} flowTimeExtent - Time extent [min, max]
 * @param {string} format - Format string
 */
async function handleChunkedFlowsFormat(detail, manifest, totalFlows, flowTimeExtent, format) {
    const chunksMeta = detail.chunksMeta;
    const loadChunksForTimeRange = detail.loadChunksForTimeRange;

    console.log(`[FlowData] Received metadata for ${chunksMeta.length} chunks, ${totalFlows} total flows`);

    // Create synthetic flows from chunk metadata for overview binning
    const syntheticFlows = createSyntheticFlowsFromChunks(chunksMeta);
    logSyntheticFlowRange(syntheticFlows, flowTimeExtent, state.timearcs.overviewTimeExtent);

    // Store synthetic flows for the overview chart
    state.flows.tcp = syntheticFlows;
    state.flows.current = syntheticFlows;

    // Initialize adaptive loader or fall back to single-resolution
    const basePath = detail.basePath || 'packets_data/attack_flows_day1to5';
    const effectiveExtent = state.timearcs.overviewTimeExtent || flowTimeExtent;

    const { loader, initialized } = await initializeAdaptiveLoader({
        basePath,
        AdaptiveOverviewLoaderClass: AdaptiveOverviewLoader,
        currentLoader: adaptiveOverviewLoader,
        effectiveExtent
    });

    if (initialized && loader) {
        adaptiveOverviewLoader = loader;
    }

    const hasAdaptiveOverview = initialized;

    // Fall back to single-resolution flow_bins.json if adaptive loader not available
    let flowBins = null;
    if (!hasAdaptiveOverview) {
        console.log('[FlowData] Multi-resolution index not found, trying single-resolution fallback...');
        flowBins = await loadFlowBinsFallback(basePath);
    }

    // Load ip_pair_overview.json for instant overview chart rendering
    const ipPairOverview = await loadIpPairOverview(basePath);

    // Try to load flow_list.json for flow list popup (lighter alternative to chunks)
    const hasFlowList = await tryLoadFlowList(basePath);
    if (hasFlowList) {
        console.log('[FlowData] flow_list.json loaded - flow list popup will use summary data');
    }

    // Store flow state for on-demand loading
    flowDataState = {
        chunksMeta,
        pairsMeta: detail.pairsMeta,
        manifest,
        totalFlows,
        timeExtent: flowTimeExtent,
        format,
        loadChunksForTimeRange,
        getChunkPath: detail.getChunkPath,
        basePath,
        flowBins,
        ipPairOverview,
        hasAdaptiveOverview,
        hasFlowList
    };

    // Update UI
    updateFlowDataUI({ totalFlows, chunkCount: chunksMeta.length, format: 'chunked' });

    // Defer overview chart creation to after IP selection
    console.log('[FlowData] Flow data loaded, deferring overview chart creation to after IP selection');
    console.log('[FlowData] Applying TimeArcs brush selection pre-filter...');
    applyBrushSelectionPrefilter();
}

/**
 * Handle legacy flows format (direct flow objects)
 * @param {Object} detail - Event detail object
 * @param {Object} manifest - Data manifest
 * @param {Array} flowTimeExtent - Time extent [min, max]
 */
function handleLegacyFlowsFormat(detail, manifest, flowTimeExtent) {
    const flows = detail.flows;
    state.flows.tcp = flows;
    state.flows.current = flows;

    flowDataState = {
        flows,
        manifest,
        totalFlows: flows.length,
        timeExtent: flowTimeExtent,
        format: 'chunked_flows'
    };

    const { width, margins } = calculateChartDimensions();
    const effectiveExtent = state.timearcs.overviewTimeExtent || flowTimeExtent;
    createOverviewChart([], { timeExtent: effectiveExtent, width, margins });
}

/**
 * Handle multires flows format (pre-binned overview bins)
 * @param {Object} detail - Event detail object
 * @param {Object} manifest - Data manifest
 * @param {number} totalFlows - Total flow count
 * @param {Array} flowTimeExtent - Time extent [min, max]
 */
function handleMultiresFlowsFormat(detail, manifest, totalFlows, flowTimeExtent) {
    const { overviewBins, flowResolutionState, loadFlowsForTimeRange } = detail;

    // Store flow state for on-demand loading
    flowDataState = {
        overviewBins,
        manifest,
        flowResolutionState,
        loadFlowsForTimeRange,
        totalFlows,
        timeExtent: flowTimeExtent
    };

    // Update UI
    updateFlowDataUI({ totalFlows, format: 'multires' });

    console.log(`[FlowData] Stored flow state: ${totalFlows} flows available for on-demand loading`);

    // Create the flow overview chart
    if (overviewBins && overviewBins.length > 0) {
        const { width, margins } = calculateChartDimensions();

        // Debug: check sample bin data
        const sampleBin = overviewBins[Math.floor(overviewBins.length / 2)];
        console.log('[FlowData] Sample bin:', sampleBin);
        console.log(`[FlowData] Chart dimensions: width=${width}, flowTimeExtent=`, flowTimeExtent);

        const effectiveExtent = state.timearcs.overviewTimeExtent || flowTimeExtent;
        createFlowOverviewChart(overviewBins, {
            timeExtent: effectiveExtent,
            width,
            margins,
            loadFlowsForTimeRange
        });

        console.log(`[FlowData] Created flow overview chart with ${overviewBins.length} bins`);
    } else {
        console.warn('[FlowData] No overview bins to display');
    }
}

/**
 * Get the current flow data state
 */
function getFlowDataState() {
    return flowDataState;
}

/**
 * Load flows for currently selected IPs and visible time range
 */
async function loadFlowsForCurrentView() {
    if (!flowDataState || !flowDataState.loadFlowsForTimeRange) {
        console.log('[FlowData] No flow data available');
        return [];
    }

    // Get current visible time range from the visualization
    const visibleExtent = getVisibleTimeExtent();
    if (!visibleExtent) {
        console.log('[FlowData] No visible time extent');
        return [];
    }

    console.log(`[FlowData] Loading flows for time range: ${visibleExtent[0]} - ${visibleExtent[1]}`);
    const flows = await flowDataState.loadFlowsForTimeRange(visibleExtent[0], visibleExtent[1]);

    // Filter by selected IPs if any
    if (selectedIPs && selectedIPs.length > 0) {
        const ipSet = new Set(selectedIPs);
        return flows.filter(f => ipSet.has(f.initiator) || ipSet.has(f.responder));
    }

    return flows;
}

/**
 * Get current visible time extent from visualization
 */
function getVisibleTimeExtent() {
    // Try to get from scales
    if (window.xScale && typeof window.xScale.domain === 'function') {
        const domain = window.xScale.domain();
        if (domain && domain.length === 2) {
            return [domain[0].getTime() * 1000, domain[1].getTime() * 1000];
        }
    }
    // Fallback to full data extent
    if (state.data.full && state.data.full.length > 0) {
        const times = state.data.full.map(d => d.timestamp || d.binStart || d.binCenter);
        return [Math.min(...times), Math.max(...times)];
    }
    return null;
}

// Default data path for auto-loading
const DEFAULT_DATA_PATH = 'packets_data/attack_packets_day1to5';
const DEFAULT_FLOW_DATA_PATH = 'packets_data/attack_flows_day1to5';

// ============================================================================
// Fetch-based Multi-Resolution Manager
// Handles dynamic loading of millisecond and raw resolution data via fetch()
// ============================================================================

/**
 * Single configuration for all resolution levels (fetch-based manager).
 * Order matters: first match wins (check from top to bottom).
 *
 * Thresholds:
 * - hours: > 2 days visible
 * - minutes: > 1 hour visible
 * - seconds: > 1 minute visible
 * - 100ms: > 10 seconds visible
 * - 10ms: > 1 second visible
 * - 1ms: > 100ms visible
 * - raw: <= 100ms visible
 */
const FETCH_RES_CONFIG = [
    {
        name: 'hours',
        dirName: 'hours',
        threshold: 2 * 24 * 60 * 60 * 1_000_000, // > 2 days visible: use hours
        binSize: 3_600_000_000,          // 1 hour in microseconds
        preBinned: true,
        isSingleFile: true,
        cacheSize: 0,
        uiInfo: { label: 'Hours', icon: '🕐', color: '#20c997' }
    },
    {
        name: 'minutes',
        dirName: 'minutes',
        threshold: 60 * 60 * 1_000_000,  // > 1 hour visible: use minutes
        binSize: 60_000_000,             // 1 minute in microseconds
        preBinned: true,
        isSingleFile: true,
        cacheSize: 0,
        uiInfo: { label: 'Minutes', icon: '🕑', color: '#17a2b8' }
    },
    {
        name: 'seconds',
        dirName: 'seconds',
        threshold: 60 * 1_000_000,       // > 1 minute visible: use seconds
        binSize: 1_000_000,
        preBinned: true,
        isSingleFile: true,
        cacheSize: 0,
        uiInfo: { label: 'Seconds', icon: '📊', color: '#28a745' }
    },
    {
        name: '100ms',
        dirName: '100ms',
        threshold: 10 * 1_000_000,       // > 10s visible: use 100ms
        binSize: 100_000,
        preBinned: true,
        isSingleFile: false,
        cacheSize: 30,
        uiInfo: { label: '100ms', icon: '⏱', color: '#17a2b8' }
    },
    {
        name: '10ms',
        dirName: '10ms',
        threshold: 1 * 1_000_000,        // > 1s visible: use 10ms
        binSize: 10_000,
        preBinned: true,
        isSingleFile: false,
        cacheSize: 40,
        uiInfo: { label: '10ms', icon: '⏱', color: '#007bff' }
    },
    {
        name: '1ms',
        dirName: '1ms',
        threshold: 100_000,              // > 100ms visible: use 1ms
        binSize: 1_000,
        preBinned: true,
        isSingleFile: false,
        cacheSize: 50,
        uiInfo: { label: '1ms', icon: '⏱', color: '#6610f2' }
    },
    {
        name: 'raw',
        dirName: 'raw',
        threshold: 0,               // < 100ms visible: use raw
        binSize: 1,
        preBinned: false,
        isSingleFile: false,
        cacheSize: 50,
        uiInfo: { label: 'Raw Packets', icon: '📦', color: '#6c757d' }
    },
    // Fallback entry for client-side binning (not a real resolution level)
    {
        name: 'binned',
        dirName: null,
        threshold: -1,
        binSize: 0,
        preBinned: false,
        isSingleFile: false,
        cacheSize: 0,
        uiInfo: { label: 'Client Binned', icon: '🔄', color: '#fd7e14' }
    }
];

// Build lookup map for quick access by name
const FETCH_RES_BY_NAME = Object.fromEntries(
    FETCH_RES_CONFIG.map(r => [r.name, r])
);

// Fetch-based resolution manager state (dynamic, config-driven)
const fetchResManager = {
    basePath: null,
    indices: new Map(),            // resolution name -> index data
    caches: new Map(),             // resolution name -> Map (chunk cache)
    singleFileData: new Map(),     // resolution name -> data array
    loadingChunks: new Set(),
    initialized: false,
    timeExtent: null,
    selectedIPs: [],
    selectedIPSet: new Set()
};

// Initialize caches based on config
for (const res of FETCH_RES_CONFIG) {
    if (!res.isSingleFile && res.cacheSize > 0) {
        fetchResManager.caches.set(res.name, new Map());
    }
}

/**
 * Set the selected IPs for filtering multi-res data
 * Called from updateIPFilter when user selects/deselects IPs
 */
function setFetchResSelectedIPs(ips) {
    fetchResManager.selectedIPs = ips || [];
    fetchResManager.selectedIPSet = new Set(fetchResManager.selectedIPs);
    console.log(`[FetchResManager] Selected IPs updated: ${fetchResManager.selectedIPs.length} IPs`);
}

/**
 * Initialize the fetch-based resolution manager
 */
async function initFetchResolutionManager(basePath) {
    console.log('[FetchResManager] Initializing...');
    fetchResManager.basePath = basePath;

    // Load indices for all resolutions based on config
    for (const res of FETCH_RES_CONFIG) {
        if (res.isSingleFile || !res.dirName) continue;  // Skip single-file and fallback entries

        try {
            const indexResp = await fetch(`${basePath}/resolutions/${res.dirName}/index.json`);
            if (indexResp.ok) {
                const index = await indexResp.json();
                fetchResManager.indices.set(res.name, index);
                console.log(`[FetchResManager] Loaded ${res.name} index: ${index.chunks?.length || 0} chunks`);
            }
        } catch (err) {
            console.warn(`[FetchResManager] Failed to load ${res.name} index:`, err);
        }
    }

    fetchResManager.initialized = true;

    // Set global functions for the zoom handler to use
    getMultiResData = fetchGetMultiResData;
    isMultiResAvailable = () => fetchResManager.initialized;
    getCurrentResolution = () => currentResolutionLevel;
    setMultiResSelectedIPs = setFetchResSelectedIPs;

    console.log('[FetchResManager] Initialization complete');
}

/**
 * Map overview chart resolution to packets view resolution
 * Overview uses: '1s', '1min', '10min', 'hour'
 * Packets use: 'seconds', 'minutes', 'hours', etc.
 */
const OVERVIEW_TO_PACKET_RESOLUTION = {
    '1s': 'seconds',
    '1min': 'minutes',
    '10min': 'minutes',  // No 10min in packets, use minutes
    'hour': 'hours'
};

/**
 * Determine which resolution to use based on visible range
 * On initial load: sync with overview chart resolution
 * After initial load: use threshold-based logic for free zoom to finer levels
 */
function getResolutionForVisibleRange(visibleRangeUs) {
    // Sanity check: if visible range is invalid or zero, default to hours
    if (!visibleRangeUs || visibleRangeUs <= 0) {
        console.log(`[Resolution] Invalid visible range (${visibleRangeUs}), defaulting to hours`);
        return 'hours';
    }

    // On initial load only: sync with overview chart resolution
    if (isInitialResolutionLoad && adaptiveOverviewLoader && adaptiveOverviewLoader.index) {
        const timeRangeMinutes = visibleRangeUs / 60_000_000;
        const overviewRes = adaptiveOverviewLoader.selectResolution(timeRangeMinutes);
        const mappedRes = OVERVIEW_TO_PACKET_RESOLUTION[overviewRes];
        if (mappedRes && FETCH_RES_BY_NAME[mappedRes]) {
            console.log(`[Resolution] Initial load sync: ${timeRangeMinutes.toFixed(1)} min → overview=${overviewRes} → packets=${mappedRes}`);
            // Mark initial load as done - subsequent zooms use threshold logic
            isInitialResolutionLoad = false;
            return mappedRes;
        }
    }

    // After initial load (or if no overview): use threshold-based logic for all zoom levels
    for (const res of FETCH_RES_CONFIG) {
        // Skip 'binned' - it's only for client-side binning, not a real resolution
        if (res.name === 'binned') continue;
        if (visibleRangeUs > res.threshold) {
            console.log(`[Resolution] Threshold: ${(visibleRangeUs/1_000_000).toFixed(2)}s → ${res.name}`);
            return res.name;
        }
    }
    // Default to finest available resolution if nothing matched
    return '1ms';
}

/**
 * Get data for the current zoom level (called by zoom handler)
 * @param {d3.scaleLinear} xScale - Current x scale
 * @param {number} zoomLevel - Zoom level (not directly used, we calculate from domain)
 * @returns {Promise<{data: Array, resolution: string, preBinned: boolean}>}
 */
async function fetchGetMultiResData(xScale, zoomLevel) {
    if (!fetchResManager.initialized) {
        return { data: [], resolution: 'hours', preBinned: true };
    }

    const domain = xScale.domain();
    const [start, end] = [Math.floor(domain[0]), Math.floor(domain[1])];
    const visibleRange = end - start;

    const resolution = getResolutionForVisibleRange(visibleRange);
    const resConfig = FETCH_RES_BY_NAME[resolution];
    console.log(`[FetchResManager] Visible range: ${(visibleRange/1_000_000).toFixed(2)}s, Resolution: ${resolution}`);

    // Helper: filter data by selected IPs (only include rows where both src and dst are selected)
    const filterBySelectedIPs = (data) => {
        const ipSet = fetchResManager.selectedIPSet;
        if (ipSet.size < 2) {
            return [];  // Need at least 2 IPs to show any connection
        }
        return data.filter(d => ipSet.has(d.src_ip) && ipSet.has(d.dst_ip));
    };

    // For single-file resolutions (hours, minutes, seconds), use pre-loaded data
    if (resConfig?.isSingleFile) {
        const preloadedData = fetchResManager.singleFileData.get(resolution);
        if (preloadedData) {
            let filtered = preloadedData.filter(d => {
                const t = d.binStart || d.timestamp;
                return t >= start && t <= end;
            });
            filtered = filterBySelectedIPs(filtered);
            return { data: filtered, resolution, preBinned: resConfig.preBinned };
        }
        // Fall back to state.data.full
        let filtered = state.data.full.filter(d => {
            const t = d.binStart || d.timestamp;
            return t >= start && t <= end;
        });
        filtered = filterBySelectedIPs(filtered);
        return { data: filtered, resolution, preBinned: true };
    }

    // For chunked resolutions, fetch from chunks
    let data = await fetchChunksForRange(start, end, resolution);
    data = filterBySelectedIPs(data);
    return { data, resolution, preBinned: resConfig?.preBinned !== false };
}

/**
 * Get index and cache for a given resolution
 */
function getIndexAndCacheForResolution(resolution) {
    return {
        index: fetchResManager.indices.get(resolution),
        cache: fetchResManager.caches.get(resolution)
    };
}

/**
 * Fetch and assemble data from chunks for a time range
 */
async function fetchChunksForRange(start, end, resolution) {
    const { index, cache } = getIndexAndCacheForResolution(resolution);

    if (!index || !index.chunks) {
        console.warn(`[FetchResManager] No ${resolution} index available`);
        return [];
    }

    // Find chunks that overlap with the requested range
    const neededChunks = index.chunks.filter(chunk =>
        chunk.end >= start && chunk.start <= end
    );

    console.log(`[FetchResManager] Need ${neededChunks.length} ${resolution} chunks for range [${start}, ${end}]`);

    // Load any chunks not in cache
    const loadPromises = [];
    for (const chunk of neededChunks) {
        if (!cache.has(chunk.file) && !fetchResManager.loadingChunks.has(chunk.file)) {
            loadPromises.push(loadChunk(chunk, resolution));
        }
    }

    // Wait for all chunks to load
    if (loadPromises.length > 0) {
        console.log(`[FetchResManager] Loading ${loadPromises.length} ${resolution} chunks...`);
        await Promise.all(loadPromises);
    }

    // Assemble data from cache
    const allData = [];
    for (const chunk of neededChunks) {
        const chunkData = cache.get(chunk.file);
        if (chunkData) {
            // Filter to exact range
            const filtered = chunkData.filter(d => {
                const t = d.binStart || d.timestamp;
                return t >= start && t <= end;
            });
            allData.push(...filtered);
        }
    }

    // Sort by timestamp
    allData.sort((a, b) => (a.timestamp || a.binStart) - (b.timestamp || b.binStart));

    console.log(`[FetchResManager] Assembled ${allData.length} ${resolution} data points`);
    return allData;
}

/**
 * Load a single chunk from the server
 */
async function loadChunk(chunk, resolution) {
    const { cache } = getIndexAndCacheForResolution(resolution);
    const resConfig = FETCH_RES_BY_NAME[resolution];

    if (!cache || !resConfig) {
        console.warn(`[FetchResManager] Unknown resolution: ${resolution}`);
        return;
    }

    fetchResManager.loadingChunks.add(chunk.file);

    try {
        const url = `${fetchResManager.basePath}/resolutions/${resConfig.dirName}/${chunk.file}`;
        console.log(`[FetchResManager] Loading: ${url}`);

        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const csvText = await response.text();
        // Use config to determine parsing: preBinned uses binned parser, otherwise raw
        const data = resConfig.preBinned
            ? parseBinnedCSV(csvText, resConfig)
            : parseRawCSV(csvText, resConfig);

        // Add to cache (with LRU eviction based on config)
        const maxSize = resConfig.cacheSize || 30;
        if (cache.size >= maxSize) {
            const oldest = cache.keys().next().value;
            cache.delete(oldest);
        }
        cache.set(chunk.file, data);

        console.log(`[FetchResManager] Loaded ${chunk.file}: ${data.length} items`);

    } catch (err) {
        console.error(`[FetchResManager] Failed to load ${chunk.file}:`, err);
    } finally {
        fetchResManager.loadingChunks.delete(chunk.file);
    }
}

/**
 * Generic CSV parser for packet/bin data
 * Consolidates parseBinnedCSV, parseRawCSV, and parseSecondsCSV
 * @param {string} csvText - CSV text to parse
 * @param {Object} config - Parser configuration
 * @param {string[]} config.numericFields - Fields to parse as integers
 * @param {boolean} config.binned - Whether data is pre-binned (affects metadata)
 * @param {number} config.binSize - Bin size in microseconds (for binned data)
 * @param {string} config.resolution - Resolution name string
 * @param {number} config.progressInterval - Log progress every N lines (0 = disabled)
 * @returns {Array} Parsed data objects
 */
function parsePacketCSV(csvText, config = {}) {
    const {
        numericFields = [],
        binned = false,
        binSize = 1_000_000,
        resolution = 'unknown',
        progressInterval = 0
    } = config;

    const lines = csvText.split('\n').filter(line => line.trim().length > 0);
    if (lines.length < 2) return [];

    const headers = lines[0].split(',').map(h => h.trim());
    const data = [];
    const numericSet = new Set(numericFields);

    for (let i = 1; i < lines.length; i++) {
        const values = lines[i].split(',');
        if (values.length < headers.length) continue;

        const row = {};
        for (let j = 0; j < headers.length; j++) {
            const header = headers[j];
            let value = values[j]?.trim() || '';
            if (numericSet.has(header)) {
                value = parseInt(value) || 0;
            }
            row[header] = value;
        }

        // Common metadata
        row.binned = binned;
        row.flagType = row.flag_type || 'OTHER';
        row.resolution = resolution;

        // Binned data gets additional metadata
        if (binned) {
            row.binStart = row.bin_start || row.timestamp;
            row.binEnd = row.bin_end || (row.timestamp + binSize);
            row.binCenter = Math.floor((row.binStart + row.binEnd) / 2);
            row.flags = flagTypeToFlags(row.flag_type);
            row.length = row.total_bytes || 0;
            row.preBinnedSize = row.binEnd - row.binStart;
        }

        data.push(row);

        // Optional progress logging
        if (progressInterval > 0 && i % progressInterval === 0) {
            console.log(`[parsePacketCSV] Parsed ${i}/${lines.length} ${resolution} rows...`);
        }
    }

    return data;
}

/** Parse binned CSV - thin wrapper for backwards compatibility */
function parseBinnedCSV(csvText, resConfig) {
    return parsePacketCSV(csvText, {
        numericFields: ['timestamp', 'bin_start', 'bin_end', 'count', 'total_bytes'],
        binned: true,
        binSize: resConfig?.binSize || 1_000,
        resolution: resConfig?.name || 'unknown'
    });
}

/** Parse raw CSV (individual packets) - thin wrapper for backwards compatibility */
function parseRawCSV(csvText, resConfig = null) {
    return parsePacketCSV(csvText, {
        numericFields: ['timestamp', 'src_port', 'dst_port', 'flags', 'length'],
        binned: false,
        resolution: resConfig?.name || 'raw'
    });
}

/**
 * Load CSV multi-resolution data from a specific path via fetch()
 * This allows loading data without requiring File System Access API
 * @param {string} basePath - Base path to the data folder (default: packets_data/attack_packets_first5days_multires)
 */
async function loadFromPath(basePath = DEFAULT_DATA_PATH) {
    console.log(`[loadFromPath] Loading data from: ${basePath}`);

    try {
        // Show loading progress
        try { sbShowCsvProgress('Loading manifest...', 0); } catch(e) { logCatchError('sbShowCsvProgress', e); }

        // Load manifest.json
        const manifestResponse = await fetch(`${basePath}/manifest.json`);
        if (!manifestResponse.ok) {
            throw new Error(`Failed to load manifest.json: ${manifestResponse.status}`);
        }
        const manifest = await manifestResponse.json();
        console.log('[loadFromPath] Loaded manifest:', manifest);

        // Check for flow-based format (from tcp_flow_detector_multires.py)
        if (manifest.format === 'multires_flows') {
            console.log('[loadFromPath] Flow-based format detected, using flow loader');
            return await loadFlowsFromPath(basePath, manifest);
        }

        try { sbUpdateCsvProgress(0.1, 'Loading hours index...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }

        // Load hours resolution (initial/default zoomed-out view)
        const hoursIndexResponse = await fetch(`${basePath}/resolutions/hours/index.json`);
        if (!hoursIndexResponse.ok) {
            throw new Error(`Failed to load hours index: ${hoursIndexResponse.status}`);
        }
        const hoursIndex = await hoursIndexResponse.json();
        console.log('[loadFromPath] Loaded hours index:', hoursIndex);

        try { sbUpdateCsvProgress(0.2, 'Loading hours data...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }

        // Load hours data CSV
        const hoursDataFile = hoursIndex.data_file || 'data.csv';
        const hoursDataResponse = await fetch(`${basePath}/resolutions/hours/${hoursDataFile}`);
        if (!hoursDataResponse.ok) {
            throw new Error(`Failed to load hours data: ${hoursDataResponse.status}`);
        }
        const hoursCsvText = await hoursDataResponse.text();
        console.log(`[loadFromPath] Loaded hours CSV: ${hoursCsvText.length} bytes`);

        try { sbUpdateCsvProgress(0.35, 'Parsing hours data...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }

        // Parse the hours CSV data
        const hoursPackets = parseSecondsCSV(hoursCsvText, 'hours');
        console.log(`[loadFromPath] Parsed ${hoursPackets.length} hour-level bins`);

        // Also preload minutes and seconds data (all single-file resolutions)
        let minutesPackets = [];
        let secondsPackets = [];

        try { sbUpdateCsvProgress(0.45, 'Loading minutes data...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }

        try {
            const minutesIndexResponse = await fetch(`${basePath}/resolutions/minutes/index.json`);
            if (minutesIndexResponse.ok) {
                const minutesIndex = await minutesIndexResponse.json();
                const minutesDataFile = minutesIndex.data_file || 'data.csv';
                const minutesDataResponse = await fetch(`${basePath}/resolutions/minutes/${minutesDataFile}`);
                if (minutesDataResponse.ok) {
                    const minutesCsvText = await minutesDataResponse.text();
                    minutesPackets = parseSecondsCSV(minutesCsvText, 'minutes');
                    console.log(`[loadFromPath] Preloaded ${minutesPackets.length} minute-level bins`);
                }
            }
        } catch (e) {
            console.warn('[loadFromPath] Could not preload minutes data:', e);
        }

        try { sbUpdateCsvProgress(0.55, 'Loading seconds data...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }

        try {
            const secondsIndexResponse = await fetch(`${basePath}/resolutions/seconds/index.json`);
            if (secondsIndexResponse.ok) {
                const secondsIndex = await secondsIndexResponse.json();
                const secondsDataFile = secondsIndex.data_file || 'data.csv';
                const secondsDataResponse = await fetch(`${basePath}/resolutions/seconds/${secondsDataFile}`);
                if (secondsDataResponse.ok) {
                    const secondsCsvText = await secondsDataResponse.text();
                    secondsPackets = parseSecondsCSV(secondsCsvText, 'seconds');
                    console.log(`[loadFromPath] Preloaded ${secondsPackets.length} second-level bins`);
                }
            }
        } catch (e) {
            console.warn('[loadFromPath] Could not preload seconds data:', e);
        }

        // Use finest available single-file resolution for initial data
        // Prefer seconds > minutes > hours for better compatibility with typical user selections
        let packets;
        let initialResolution;
        if (secondsPackets.length > 0) {
            packets = secondsPackets;
            initialResolution = 'seconds';
        } else if (minutesPackets.length > 0) {
            packets = minutesPackets;
            initialResolution = 'minutes';
        } else {
            packets = hoursPackets;
            initialResolution = 'hours';
        }
        console.log(`[loadFromPath] Using ${packets.length} ${initialResolution}-level bins as initial data`);

        if (packets.length === 0) {
            throw new Error('No data parsed from seconds CSV');
        }

        try { sbUpdateCsvProgress(0.8, 'Extracting IP addresses...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }

        // Extract unique IPs
        const uniqueIPs = extractUniqueIPsFromPackets(packets);
        console.log(`[loadFromPath] Found ${uniqueIPs.length} unique IPs`);

        try { sbUpdateCsvProgress(0.9, 'Initializing visualization...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }

        // Set global data
        state.data.full = packets;
        state.data.filtered = [];
        state.data.isPreBinned = true;  // Seconds data is pre-binned
        useMultiRes = true;

        // For now, no TCP flows from this format (flows would require separate loading)
        state.flows.tcp = [];
        state.flows.current = [];
        state.flows.selectedIds.clear();

        // Create IP checkboxes
        createIPCheckboxes(uniqueIPs);

        // Update TCP flow stats
        updateTcpFlowStats(state.flows.current);

        // Initialize web worker
        try {
            if (!workerManager) {
                initializeWorkerManager();
            }
        } catch (err) {
            console.error('Worker init failed', err);
        }

        // Show message asking user to select IPs
        document.getElementById('loadingMessage').textContent =
            `Loaded ${packets.length.toLocaleString()} ${initialResolution}-level bins with ${uniqueIPs.length} IPs. Please select 2+ IP addresses to view connections.`;
        document.getElementById('loadingMessage').style.display = 'block';

        try { sbUpdateCsvProgress(0.95, 'Initializing multi-resolution manager...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }

        // Initialize the fetch-based resolution manager for higher-resolution data on zoom
        // Store all single-file resolution data in the manager
        fetchResManager.singleFileData.set('hours', hoursPackets);
        if (minutesPackets.length > 0) {
            fetchResManager.singleFileData.set('minutes', minutesPackets);
        }
        if (secondsPackets.length > 0) {
            fetchResManager.singleFileData.set('seconds', secondsPackets);
        }
        await initFetchResolutionManager(basePath);

        try { sbUpdateCsvProgress(1.0, 'Data loaded successfully!'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }

        // Hide progress after brief delay
        setTimeout(() => {
            try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }
        }, 1000);

        console.log(`[loadFromPath] Successfully loaded ${packets.length} hour-level bins from ${basePath}`);
        console.log(`[loadFromPath] Multi-resolution manager ready with ${fetchResManager.indices.size} resolution indices`);
        console.log(`[loadFromPath] Preloaded single-file resolutions: hours(${hoursPackets.length}), minutes(${minutesPackets.length}), seconds(${secondsPackets.length})`);

        // Don't set initial zoom indicator here - wait for overview chart to determine resolution
        // The onResolutionChange callback will sync the packets view with the overview
        console.log(`[loadFromPath] Deferring zoom indicator until overview resolution is determined`);

        // Store packet time extent for later use if needed
        const packetTimeExtent = d3.extent(packets, d => d.binStart || d.timestamp);
        console.log(`[loadFromPath] Packet time extent:`, packetTimeExtent);

    } catch (err) {
        console.error('[loadFromPath] Error loading data:', err);
        try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }

        // Show error in loading message
        const loadingMsg = document.getElementById('loadingMessage');
        if (loadingMsg) {
            loadingMsg.textContent = `Error loading data: ${err.message}. Try using the file picker instead.`;
            loadingMsg.style.display = 'block';
            loadingMsg.style.color = '#e74c3c';
        }
    }
}

/**
 * Load flow data from a path using fetch (for default/auto-loading)
 * Supports both chunked_flows (v2) and chunked_flows_by_ip_pair (v3) formats
 * @param {string} basePath - Path to the flow data folder
 */
async function loadFlowsFromPath(basePath = DEFAULT_FLOW_DATA_PATH) {
    console.log(`[loadFlowsFromPath] Loading flow data from: ${basePath}`);

    try {
        // Load manifest
        const manifestResponse = await fetch(`${basePath}/manifest.json`);
        if (!manifestResponse.ok) {
            throw new Error(`Failed to load manifest: ${manifestResponse.status}`);
        }
        const manifest = await manifestResponse.json();
        console.log('[loadFlowsFromPath] Loaded manifest:', manifest);

        const format = manifest.format;
        let chunksMeta = [];
        let pairsMeta = null;
        let getChunkPath;

        if (format === 'chunked_flows_by_ip_pair') {
            // v3 format: flows organized by IP pair
            console.log('[loadFlowsFromPath] Using chunked_flows_by_ip_pair format');

            const pairsMetaResponse = await fetch(`${basePath}/flows/pairs_meta.json`);
            if (!pairsMetaResponse.ok) {
                throw new Error(`Failed to load pairs_meta.json: ${pairsMetaResponse.status}`);
            }
            pairsMeta = await pairsMetaResponse.json();
            console.log(`[loadFlowsFromPath] Loaded metadata for ${pairsMeta.length} IP pairs`);

            // Flatten all chunks from all pairs into a single array with folder info
            for (const pair of pairsMeta) {
                for (const chunk of pair.chunks) {
                    chunksMeta.push({
                        ...chunk,
                        folder: pair.folder,
                        ips: pair.ips
                    });
                }
            }
            console.log(`[loadFlowsFromPath] Flattened to ${chunksMeta.length} total chunks`);

            // Chunk path for v3: flows/by_pair/{folder}/{file}
            getChunkPath = (chunk) => `${basePath}/flows/by_pair/${chunk.folder}/${chunk.file}`;

        } else if (format === 'chunked_flows') {
            // v2 format: flat chunks
            console.log('[loadFlowsFromPath] Using chunked_flows format');

            const chunksMetaResponse = await fetch(`${basePath}/flows/chunks_meta.json`);
            if (!chunksMetaResponse.ok) {
                throw new Error(`Failed to load chunks_meta.json: ${chunksMetaResponse.status}`);
            }
            chunksMeta = await chunksMetaResponse.json();
            console.log(`[loadFlowsFromPath] Loaded metadata for ${chunksMeta.length} chunks`);

            // Chunk path for v2: flows/{file}
            getChunkPath = (chunk) => `${basePath}/flows/${chunk.file}`;

        } else {
            throw new Error(`Unsupported format: ${format}`);
        }

        // Calculate totals from metadata
        let totalFlows = 0;
        let minTime = Infinity, maxTime = -Infinity;
        for (const chunk of chunksMeta) {
            totalFlows += chunk.count || 0;
            if (chunk.start && chunk.start < minTime) minTime = chunk.start;
            if (chunk.end && chunk.end > maxTime) maxTime = chunk.end;
        }
        const flowTimeExtent = [minTime, maxTime];

        console.log(`[loadFlowsFromPath] Total flows: ${totalFlows}, time extent:`, flowTimeExtent);

        // Initialize adaptive overview loader early for resolution sync
        // This allows the packets view to determine resolution matching the overview chart
        try {
            const indexPath = `${basePath}/indices/flow_bins_index.json`;
            console.log(`[loadFlowsFromPath] Checking for multi-resolution index at ${indexPath}...`);
            const indexResponse = await fetch(indexPath);
            if (indexResponse.ok) {
                adaptiveOverviewLoader = new AdaptiveOverviewLoader(basePath);
                await adaptiveOverviewLoader.loadIndex();

                // Set initial resolution based on full time extent - MUST happen before any IP selection
                const initialTimeRangeMinutes = (flowTimeExtent[1] - flowTimeExtent[0]) / 60_000_000;
                adaptiveOverviewLoader.currentResolution = adaptiveOverviewLoader.selectResolution(initialTimeRangeMinutes);
                console.log(`[loadFlowsFromPath] ✓ Adaptive overview loader initialized with resolutions:`,
                    Object.keys(adaptiveOverviewLoader.index.resolutions),
                    `initial resolution: ${adaptiveOverviewLoader.currentResolution} (${initialTimeRangeMinutes.toFixed(1)} min range)`);

                // Capture flow time extent for fallback
                const capturedFlowTimeExtent = flowTimeExtent.slice();

                // Set up callback to sync zoom indicator when overview resolution changes
                // The callback receives the time range directly from the overview loader
                adaptiveOverviewLoader.onResolutionChange = (newResolution, oldResolution, timeInfo) => {
                    console.log(`[Resolution Sync] Overview resolution changed: ${oldResolution} → ${newResolution}`, timeInfo);
                    const mappedRes = OVERVIEW_TO_PACKET_RESOLUTION[newResolution];
                    if (mappedRes && FETCH_RES_BY_NAME[mappedRes]) {
                        // Get visible range from timeInfo, or compute from timeStart/timeEnd
                        let visibleRangeUs = 0;
                        if (timeInfo) {
                            visibleRangeUs = timeInfo.timeRangeUs || (timeInfo.timeEnd - timeInfo.timeStart) || 0;
                        }
                        // Fallback to xScale, state.timearcs.overviewTimeExtent, or flow extent
                        if (visibleRangeUs <= 0 && xScale) {
                            try {
                                const domain = xScale.domain();
                                visibleRangeUs = domain[1] - domain[0];
                            } catch(e) { logCatchError('xScaleDomainRead', e); }
                        }
                        if (visibleRangeUs <= 0 && state.timearcs.overviewTimeExtent) {
                            visibleRangeUs = state.timearcs.overviewTimeExtent[1] - state.timearcs.overviewTimeExtent[0];
                        }
                        if (visibleRangeUs <= 0) {
                            visibleRangeUs = capturedFlowTimeExtent[1] - capturedFlowTimeExtent[0];
                        }

                        const dataCount = fetchResManager.singleFileData.get(mappedRes)?.length || state.data.full.length;
                        updateZoomIndicator(visibleRangeUs, mappedRes, dataCount);
                        console.log(`[Resolution Sync] Updated packets view to: ${mappedRes}, range=${(visibleRangeUs/60_000_000).toFixed(1)} min, ${dataCount} points`);
                    }
                };
            }
        } catch (err) {
            console.log(`[loadFlowsFromPath] No multi-resolution index found:`, err.message);
        }

        // Create on-demand chunk loader using fetch
        const loadChunksForTimeRange = async (startTime, endTime, selectedIPs = null) => {
            const selectedIPSet = selectedIPs && selectedIPs.length > 0 ? new Set(selectedIPs) : null;

            // For v3 format, we can filter by IP pair first (much more efficient)
            let relevantChunks;
            if (format === 'chunked_flows_by_ip_pair' && selectedIPSet) {
                // Only load chunks for pairs where BOTH IPs are in the selected set
                relevantChunks = chunksMeta.filter(chunk =>
                    chunk.end >= startTime && chunk.start <= endTime &&
                    chunk.ips.every(ip => selectedIPSet.has(ip))
                );
                console.log(`[loadChunksForTimeRange] v3 IP-filtered: ${relevantChunks.length} chunks (from ${chunksMeta.length})`);
            } else {
                relevantChunks = chunksMeta.filter(chunk =>
                    chunk.end >= startTime && chunk.start <= endTime
                );
            }

            const allFlows = [];

            for (const chunk of relevantChunks) {
                try {
                    const chunkPath = getChunkPath(chunk);
                    const chunkResponse = await fetch(chunkPath);
                    if (chunkResponse.ok) {
                        const chunkFlows = await chunkResponse.json();

                        const filtered = chunkFlows.filter(f => {
                            // Filter by time range (match overview chart binning: by startTime only)
                            if (f.startTime < startTime || f.startTime >= endTime) {
                                return false;
                            }
                            // Filter by selected IPs if provided (both initiator AND responder must be in selected IPs)
                            if (selectedIPSet && (!selectedIPSet.has(f.initiator) || !selectedIPSet.has(f.responder))) {
                                return false;
                            }
                            return true;
                        });

                        allFlows.push(...filtered);
                    }
                } catch (err) {
                    console.warn(`Failed to load flow chunk ${getChunkPath(chunk)}:`, err);
                }
            }

            return allFlows;
        };

        // Dispatch flowDataLoaded event with basePath for flow detail loading
        const event = new CustomEvent('flowDataLoaded', {
            detail: {
                chunksMeta: chunksMeta,
                pairsMeta: pairsMeta,
                manifest: manifest,
                totalFlows: totalFlows,
                timeExtent: flowTimeExtent,
                format: format,
                loadChunksForTimeRange: loadChunksForTimeRange,
                getChunkPath: getChunkPath,
                basePath: basePath  // Store for flow detail loading
            }
        });
        document.dispatchEvent(event);

        // Update folder info display
        const folderInfo = document.getElementById('folderInfo');
        if (folderInfo) {
            const pairInfo = pairsMeta ? ` (${pairsMeta.length} IP pairs)` : '';
            folderInfo.innerHTML = `<span style="color: #28a745;">Flow data: ${totalFlows.toLocaleString()} flows (${chunksMeta.length} chunks${pairInfo})</span>`;
        }

        console.log(`[loadFlowsFromPath] Flow data loaded successfully`);
        return { chunksMeta, pairsMeta, manifest, totalFlows, flowTimeExtent };

    } catch (err) {
        console.error('[loadFlowsFromPath] Error loading flow data:', err);
        throw err;
    }
}

/** Parse pre-binned CSV for coarse resolutions - thin wrapper for backwards compatibility */
function parseSecondsCSV(csvText, resolution = 'seconds') {
    const binSizeMap = {
        'hours': 3_600_000_000,
        'minutes': 60_000_000,
        'seconds': 1_000_000
    };
    return parsePacketCSV(csvText, {
        numericFields: ['timestamp', 'bin_start', 'bin_end', 'count', 'total_bytes'],
        binned: true,
        binSize: binSizeMap[resolution] || 1_000_000,
        resolution,
        progressInterval: 50000
    });
}

/**
 * Convert flag_type string back to flags integer for compatibility
 */
function flagTypeToFlags(flagType) {
    const flagMap = {
        'SYN': 0x02,
        'SYN+ACK': 0x12,
        'ACK': 0x10,
        'FIN': 0x01,
        'FIN+ACK': 0x11,
        'RST': 0x04,
        'RST+ACK': 0x14,
        'PSH': 0x08,
        'PSH+ACK': 0x18,
        'URG': 0x20,
        'OTHER': 0
    };
    return flagMap[flagType] || 0;
}

/**
 * Extract unique IPs from packet data
 */
function extractUniqueIPsFromPackets(packets) {
    const ips = new Set();
    for (const p of packets) {
        if (p.src_ip) ips.add(p.src_ip);
        if (p.dst_ip) ips.add(p.dst_ip);
    }
    return Array.from(ips).sort();
}

// Set the global loadFromPath reference now that the function is defined
window.loadFromPath = loadFromPath;

// Export functions for dynamic loading
export { init, cleanup, loadFromPath };

