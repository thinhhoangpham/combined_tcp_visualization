/**
 * Flow Data Handler Module
 * Extracted from ip_bar_diagram.js handleFlowDataLoaded() function
 * Handles parsing and processing of flow data events
 */

/**
 * Detect the time unit of flow data based on extent magnitude
 * @param {number} extentMax - Maximum value in the time extent
 * @returns {{ unit: string, divisor: number }} Unit name and divisor to convert from microseconds
 */
export function detectTimeUnit(extentMax) {
    if (extentMax > 1e14) {
        return { unit: 'microseconds', divisor: 1 };
    } else if (extentMax > 1e11) {
        return { unit: 'milliseconds', divisor: 1000 };
    } else if (extentMax > 1e8) {
        return { unit: 'seconds', divisor: 1_000_000 };
    } else {
        return { unit: 'minutes', divisor: 60_000_000 };
    }
}

/**
 * Compute TimeArcs range and update state
 * Converts TimeArcs selection range to match flow data time units
 * @param {Object} params - Parameters object
 * @param {Object} params.timeRange - TimeArcs time range { minUs, maxUs } in microseconds
 * @param {Array} params.flowTimeExtent - Flow data time extent [min, max]
 * @param {Object} params.stateTimearcs - State timearcs object to update
 * @returns {{ success: boolean, extent: Array|null }} Result with computed extent
 */
export function computeTimeArcsRange({ timeRange, flowTimeExtent, stateTimearcs }) {
    console.log('[FlowData] Checking TimeArcs range:', {
        timeRange,
        overviewTimeExtent: stateTimearcs.overviewTimeExtent,
        flowTimeExtent,
        hasTimearcs: !!timeRange,
        hasOverview: !!stateTimearcs.overviewTimeExtent,
        hasFlowExtent: !!flowTimeExtent
    });

    // Check if conditions are met for range computation
    if (!timeRange || !flowTimeExtent || flowTimeExtent[0] === flowTimeExtent[1]) {
        console.log('[FlowData] Skipping TimeArcs range computation (conditions not met)');
        return { success: false, extent: null };
    }

    let { minUs, maxUs } = timeRange;

    // Safety check: if min === max (single point), expand to 60 seconds
    if (minUs === maxUs) {
        console.warn('[FlowData] TimeArcs range is a single point, expanding to 60 seconds');
        maxUs = minUs + 60_000_000;
    }

    const extentMax = Math.max(flowTimeExtent[0], flowTimeExtent[1]);

    console.log('[FlowData] Converting TimeArcs range:', {
        minUs, maxUs, extentMax, flowTimeExtent
    });

    // Detect unit and convert range
    const { unit, divisor } = detectTimeUnit(extentMax);
    const zoomMin = minUs / divisor;
    const zoomMax = maxUs / divisor;

    console.log('[FlowData] Detected unit:', unit, 'Converted range:', [zoomMin, zoomMax]);
    console.log('[FlowData] TimeArcs selection duration:', (maxUs - minUs) / 1e6, 'seconds');

    // Add small padding (5%)
    const selectedRange = zoomMax - zoomMin;
    const padding = selectedRange * 0.05;
    const paddedMin = zoomMin - padding;
    const paddedMax = zoomMax + padding;

    console.log('[FlowData] After padding:', { paddedMin, paddedMax, padding },
        'padding %:', (padding / selectedRange * 100).toFixed(1));

    // Clamp to flow data extent
    const clampedMin = Math.max(flowTimeExtent[0], paddedMin);
    const clampedMax = Math.min(flowTimeExtent[1], paddedMax);

    console.log('[FlowData] After clamping:', { clampedMin, clampedMax });

    if (clampedMin < clampedMax) {
        stateTimearcs.overviewTimeExtent = [clampedMin, clampedMax];
        stateTimearcs.intendedZoomDomain = [clampedMin, clampedMax];
        stateTimearcs.timeRange = null; // Clear after use

        console.log('[FlowData] SET state.timearcs.overviewTimeExtent:', stateTimearcs.overviewTimeExtent);
        console.log('[FlowData] Selected range duration:', (clampedMax - clampedMin) / 1e6, 'seconds');
        console.log('[FlowData] Cleared state.timearcs.timeRange after use');

        return { success: true, extent: [clampedMin, clampedMax] };
    } else {
        console.warn('[FlowData] Invalid range after clamping!', { clampedMin, clampedMax });
        return { success: false, extent: null };
    }
}

/**
 * Create synthetic flows from chunk metadata for overview binning
 * @param {Array} chunksMeta - Array of chunk metadata objects
 * @returns {Array} Array of synthetic flow objects
 */
export function createSyntheticFlowsFromChunks(chunksMeta) {
    const syntheticFlows = [];
    const INVALID_REASONS = [
        'invalid_synack', 'invalid_ack', 'rst_during_handshake',
        'incomplete_no_syn', 'incomplete_no_synack', 'incomplete_no_ack', 'unknown_invalid'
    ];

    for (const chunk of chunksMeta) {
        const centerTime = Math.floor((chunk.start + chunk.end) / 2);

        // Graceful flows
        for (let i = 0; i < (chunk.graceful || 0); i++) {
            syntheticFlows.push({ startTime: centerTime, closeType: 'graceful', state: 'closed' });
        }

        // Abortive flows
        for (let i = 0; i < (chunk.abortive || 0); i++) {
            syntheticFlows.push({ startTime: centerTime, closeType: 'abortive', state: 'aborted' });
        }

        // Invalid flows with detailed reason breakdown if available
        if (chunk.invalidReasons) {
            for (const reason of INVALID_REASONS) {
                const count = chunk.invalidReasons[reason] || 0;
                for (let i = 0; i < count; i++) {
                    syntheticFlows.push({
                        startTime: centerTime,
                        closeType: 'invalid',
                        state: 'invalid',
                        invalidReason: reason
                    });
                }
            }
        } else {
            // Fallback for older metadata without reason breakdown
            for (let i = 0; i < (chunk.invalid || 0); i++) {
                syntheticFlows.push({
                    startTime: centerTime,
                    closeType: 'invalid',
                    state: 'invalid',
                    invalidReason: 'unknown_invalid'
                });
            }
        }

        // Ongoing flows
        for (let i = 0; i < (chunk.ongoing || 0); i++) {
            syntheticFlows.push({
                startTime: centerTime,
                closeType: 'open',
                state: 'established',
                establishmentComplete: true
            });
        }
    }

    console.log(`[FlowData] Created ${syntheticFlows.length} synthetic flows for overview binning`);
    return syntheticFlows;
}

/**
 * Log synthetic flow time range for debugging
 * @param {Array} syntheticFlows - Array of synthetic flow objects
 * @param {Array} flowTimeExtent - Flow data time extent
 * @param {Array|null} overviewTimeExtent - Overview time extent from state
 */
export function logSyntheticFlowRange(syntheticFlows, flowTimeExtent, overviewTimeExtent) {
    if (syntheticFlows.length === 0) return;

    let synthMin = Infinity, synthMax = -Infinity;
    for (const f of syntheticFlows) {
        if (f.startTime < synthMin) synthMin = f.startTime;
        if (f.startTime > synthMax) synthMax = f.startTime;
    }

    console.log(`[FlowData] Synthetic flows startTime range: [${synthMin}, ${synthMax}]`);
    console.log(`[FlowData] flowTimeExtent: [${flowTimeExtent[0]}, ${flowTimeExtent[1]}]`);
    console.log(`[FlowData] overviewTimeExtent: [${overviewTimeExtent ? overviewTimeExtent[0] : 'null'}, ${overviewTimeExtent ? overviewTimeExtent[1] : 'null'}]`);
}

/**
 * Try to initialize adaptive multi-resolution overview loader
 * @param {Object} params - Parameters
 * @param {string} params.basePath - Base path to data folder
 * @param {Function} params.AdaptiveOverviewLoaderClass - Constructor for loader
 * @param {Object|null} params.currentLoader - Current loader instance (may already be initialized)
 * @param {Array|null} params.effectiveExtent - Time extent for initial resolution selection
 * @returns {Promise<{ loader: Object|null, initialized: boolean }>}
 */
export async function initializeAdaptiveLoader({ basePath, AdaptiveOverviewLoaderClass, currentLoader, effectiveExtent }) {
    // Check if already initialized
    if (currentLoader && currentLoader.index) {
        console.log('[FlowData] Adaptive overview loader already initialized');
        return { loader: currentLoader, initialized: true };
    }

    try {
        const indexPath = `${basePath}/indices/flow_bins_index.json`;
        console.log(`[FlowData] Checking for multi-resolution index at ${indexPath}...`);

        const indexResponse = await fetch(indexPath);
        if (!indexResponse.ok) {
            console.log(`[FlowData] No multi-resolution index at ${basePath}`);
            return { loader: null, initialized: false };
        }

        // Multi-resolution data available - initialize adaptive loader
        const loader = new AdaptiveOverviewLoaderClass(basePath);
        await loader.loadIndex();

        // Set initial resolution based on visible time extent
        if (effectiveExtent && effectiveExtent[0] < effectiveExtent[1]) {
            const initialTimeRangeMinutes = (effectiveExtent[1] - effectiveExtent[0]) / 60_000_000;
            loader.currentResolution = loader.selectResolution(initialTimeRangeMinutes);
            console.log(`[FlowData] Adaptive overview loader initialized from ${basePath} with resolutions:`,
                Object.keys(loader.index.resolutions),
                `initial resolution: ${loader.currentResolution} (${initialTimeRangeMinutes.toFixed(1)} min range)`);
        } else {
            console.log(`[FlowData] Adaptive overview loader initialized from ${basePath} with resolutions:`,
                Object.keys(loader.index.resolutions));
        }

        return { loader, initialized: true };
    } catch (err) {
        console.log(`[FlowData] Error initializing adaptive loader:`, err.message);
        return { loader: null, initialized: false };
    }
}

/**
 * Load single-resolution flow bins fallback
 * @param {string} basePath - Base path to data folder
 * @returns {Promise<Array|null>} Flow bins array or null
 */
export async function loadFlowBinsFallback(basePath) {
    try {
        const flowBinsPath = `${basePath}/indices/flow_bins.json`;
        console.log(`[FlowData] Loading flow bins from ${flowBinsPath}...`);

        const flowBinsResponse = await fetch(flowBinsPath);
        if (flowBinsResponse.ok) {
            const flowBins = await flowBinsResponse.json();
            console.log(`[FlowData] Loaded ${flowBins.length} flow bins (single resolution)`);
            return flowBins;
        } else {
            console.warn('[FlowData] flow_bins.json not found, will use chunk loading fallback');
            return null;
        }
    } catch (err) {
        console.warn('[FlowData] Error loading flow_bins.json:', err);
        return null;
    }
}

/**
 * Load IP pair overview data
 * @param {string} basePath - Base path to data folder
 * @returns {Promise<Object|null>} IP pair overview object or null
 */
export async function loadIpPairOverview(basePath) {
    try {
        const overviewPath = `${basePath}/indices/ip_pair_overview.json`;
        console.log(`[FlowData] Loading IP pair overview from ${overviewPath}...`);

        const overviewResponse = await fetch(overviewPath);
        if (overviewResponse.ok) {
            const ipPairOverview = await overviewResponse.json();
            console.log(`[FlowData] Loaded IP pair overview: ${Object.keys(ipPairOverview.pairs || {}).length} pairs, ${ipPairOverview.meta?.bin_count || 0} bins`);
            return ipPairOverview;
        } else {
            console.warn('[FlowData] ip_pair_overview.json not found, will use flow_bins.json or chunk loading fallback');
            return null;
        }
    } catch (err) {
        console.warn('[FlowData] Error loading ip_pair_overview.json:', err);
        return null;
    }
}

/**
 * Update flow data UI elements
 * @param {Object} params - Parameters
 * @param {number} params.totalFlows - Total flow count
 * @param {number} params.chunkCount - Number of chunks (optional)
 * @param {string} params.format - Format type ('chunked' or 'multires')
 */
export function updateFlowDataUI({ totalFlows, chunkCount = 0, format = 'chunked' }) {
    const folderInfo = document.getElementById('folderInfo');
    const tcpFlowStats = document.getElementById('tcpFlowStats');

    if (format === 'chunked' && chunkCount > 0) {
        if (folderInfo) {
            folderInfo.innerHTML += `<br><span style="color: #28a745;">Flow data: ${totalFlows.toLocaleString()} flows (${chunkCount} chunks)</span>`;
        }
        if (tcpFlowStats) {
            tcpFlowStats.innerHTML = `<span style="color: #28a745;">Flows: ${totalFlows.toLocaleString()}</span><br>
                <span style="color: #666;">Click overview bins to load details</span>`;
        }
    } else {
        if (folderInfo) {
            folderInfo.innerHTML += `<br><span style="color: #28a745;">Flow data ready: ${totalFlows.toLocaleString()} flows available</span>`;
        }
        if (tcpFlowStats) {
            tcpFlowStats.innerHTML = `<span style="color: #28a745;">Flow data loaded: ${totalFlows.toLocaleString()} flows</span><br>
                <span style="color: #666;">Click on overview chart bins to load detailed flows</span>`;
        }
    }
}

/**
 * Calculate chart dimensions from container
 * @param {string} containerId - DOM container ID
 * @param {Object} defaultMargins - Default margins object
 * @returns {{ width: number, margins: Object }}
 */
export function calculateChartDimensions(containerId = 'chart-container', defaultMargins = { left: 150, right: 120, top: 80, bottom: 50 }) {
    const container = document.getElementById(containerId);
    const containerWidth = container ? container.clientWidth : 800;
    const chartWidth = Math.max(100, containerWidth - defaultMargins.left - defaultMargins.right);
    return { width: chartWidth, margins: defaultMargins };
}
