// src/interaction/ip-filter-controller.js
// IP filter controller - orchestrates filtering and visualization updates

import { showLoadingOverlay, hideLoadingOverlay } from '../ui/loading-indicator.js';
import { getSelectedIPsFromDOM, filterPacketsByIPs } from '../data/packet-filter.js';
import { loadFlowData } from '../data/flow-loader.js';

/**
 * Create an IP filter controller factory.
 * Returns a controller with updateIPFilter method.
 *
 * @param {Object} dependencies - All required dependencies
 * @param {Object} dependencies.d3 - D3 library reference
 * @param {Function} dependencies.getState - Get current state object
 * @param {Function} dependencies.getFlowDataState - Get flow metadata state
 * @param {Function} dependencies.getAdaptiveOverviewLoader - Get adaptive loader
 * @param {Function} dependencies.getFilterCache - Get filter cache
 * @param {Function} dependencies.setMultiResSelectedIPs - Set multi-res selected IPs
 * @param {Object} dependencies.eventColors - Event color mapping
 * @param {Function} dependencies.visualizeTimeArcs - Render visualization
 * @param {Function} dependencies.drawFlagLegend - Draw flag legend
 * @param {Function} dependencies.updateIPStats - Update IP statistics
 * @param {Function} dependencies.applyTimearcsTimeRangeZoom - Apply time zoom
 * @param {Function} dependencies.computeForceLayoutPositions - Compute force layout
 * @param {Function} dependencies.updateTcpFlowStats - Update TCP flow stats
 * @param {Function} dependencies.refreshAdaptiveOverview - Refresh overview chart
 * @param {Function} dependencies.calculateGroundTruthStats - Calculate GT stats
 * @param {Function} dependencies.sbUpdateGroundTruthStatsUI - Update GT UI
 * @param {Function} dependencies.logCatchError - Error logger
 * @returns {Object} { updateIPFilter, isUpdating }
 */
export function createIPFilterController(dependencies) {
    const {
        d3,
        getState,
        getFlowDataState,
        getAdaptiveOverviewLoader,
        getFilterCache,
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
    } = dependencies;

    let isUpdating = false;

    /**
     * Main IP filter update function.
     * Filters packets and flows by selected IPs and updates visualization.
     */
    async function updateIPFilter() {
        // Prevent multiple simultaneous updates
        if (isUpdating) return;
        isUpdating = true;

        // Show loading indicator
        const loadingDiv = showLoadingOverlay(d3);

        try {
            const state = getState();
            const flowDataState = getFlowDataState();
            const adaptiveOverviewLoader = getAdaptiveOverviewLoader();
            const filterCache = getFilterCache();

            const selectedIPs = getSelectedIPsFromDOM();
            const selectedIPSet = new Set(selectedIPs);

            // Update multi-resolution loader with selected IPs for filtering
            if (setMultiResSelectedIPs) {
                setMultiResSelectedIPs(selectedIPs);
            }

            // Filter packets by selected IPs
            const { filtered } = filterPacketsByIPs({
                packets: state.data.full,
                selectedIPs,
                filterCache
            });
            state.data.filtered = filtered;
            state.data.version++;

            // Load/filter flows based on data source
            const { flows, skipSyncUpdates, hasFlowListAvailable } = await loadFlowData({
                getState,
                flowDataState,
                adaptiveOverviewLoader,
                selectedIPs,
                refreshAdaptiveOverview,
                updateTcpFlowStats,
                calculateGroundTruthStats,
                sbUpdateGroundTruthStatsUI,
                eventColors
            });

            state.flows.current = flows;

            // Skip these updates if we're doing async loading (will be done in background)
            if (!skipSyncUpdates) {
                // Clear selection to avoid stale selection across different IP filters
                state.flows.selectedIds.clear();

                // Update flow stats - show special message if flow list available but deferred
                if (hasFlowListAvailable && flows.length === 0) {
                    // Flow list CSVs available but not loaded yet - show helpful message
                    const tcpFlowStats = document.getElementById('tcpFlowStats');
                    if (tcpFlowStats) {
                        tcpFlowStats.innerHTML = `<span style="color: #28a745;">Flow List Available</span><br>
                            <span style="color: #666;">Click on overview chart bars to view flows</span><br>
                            <span style="color: #888; font-size: 11px;">Flows load on-demand for faster startup</span>`;
                    }
                } else {
                    updateTcpFlowStats(state.flows.current);
                }

                // Refresh overview chart with updated flows for selected IPs
                refreshAdaptiveOverview(selectedIPs)
                    .catch(e => console.warn('[Overview] Refresh failed:', e));

                // Update ground truth statistics
                const stats = calculateGroundTruthStats(
                    state.flows.groundTruth,
                    selectedIPs,
                    eventColors
                );
                sbUpdateGroundTruthStatsUI(stats.html, stats.hasMatches);
            }

            // Determine visualization mode
            const isFlowModeOnly = flowDataState &&
                (flowDataState.format === 'chunked_flows' || flowDataState.format === 'chunked_flows_by_ip_pair') &&
                (!state.data.filtered || state.data.filtered.length === 0);

            console.log('[updateIPFilter] Visualization decision:', {
                isFlowModeOnly,
                flowDataState: flowDataState?.format,
                filteredLength: state.data.filtered?.length,
                fullLength: state.data.full?.length,
                isPreBinned: state.data.isPreBinned
            });

            if (isFlowModeOnly) {
                // Flow mode: overview chart handles visualization
                console.log('[Visualization] Skipping packet visualization - in flow mode with no packet data');
                setTimeout(() => {
                    applyTimearcsTimeRangeZoom();
                }, 150);
            } else if (state.timearcs.ipOrder && state.timearcs.ipOrder.length > 0) {
                // Skip force layout if we have TimeArcs IP order - use it directly
                console.log('[Force Layout] Skipped - using TimeArcs vertical order');
                console.log('[updateIPFilter] Calling visualizeTimeArcs with', state.data.filtered.length, 'items');

                visualizeTimeArcs(state.data.filtered);
                try { drawFlagLegend(); } catch(e) { logCatchError('drawFlagLegend', e); }
                updateIPStats(state.data.filtered);

                setTimeout(() => {
                    applyTimearcsTimeRangeZoom();
                }, 150);
            } else {
                // Compute force layout positions for IPs before visualization
                console.log('[updateIPFilter] Using force layout path with', state.data.filtered.length, 'items');

                computeForceLayoutPositions(state.data.filtered, selectedIPs, () => {
                    console.log('[updateIPFilter] Force layout callback - calling visualizeTimeArcs');
                    visualizeTimeArcs(state.data.filtered);

                    try { drawFlagLegend(); } catch(e) { logCatchError('drawFlagLegend', e); }
                    updateIPStats(state.data.filtered);

                    setTimeout(() => {
                        applyTimearcsTimeRangeZoom();
                    }, 150);
                });
            }
        } finally {
            // Remove loading indicator
            hideLoadingOverlay(loadingDiv);
            isUpdating = false;
        }
    }

    return {
        updateIPFilter,
        isUpdating: () => isUpdating
    };
}
