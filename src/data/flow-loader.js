// src/data/flow-loader.js
// Flow loading decision tree and chunk loading utilities

import { LOG } from '../utils/formatters.js';
import {
    createProgressIndicator,
    updateProgressIndicator,
    showCompletionThenRemove
} from '../ui/loading-indicator.js';
import { getFlowListLoader } from './flow-list-loader.js';

/**
 * Filter chunks metadata to find chunks matching selected IPs and time ranges.
 * @param {Array} chunksMeta - Array of chunk metadata
 * @param {Set<string>} selectedIPSet - Set of selected IPs
 * @param {Array|null} _unused - Unused parameter (kept for API compatibility)
 * @param {Array|null} overviewTimeExtent - Optional [start, end] time filter
 * @returns {Array} Filtered chunks
 */
function filterChunks(chunksMeta, selectedIPSet, _unused, overviewTimeExtent) {
    return chunksMeta.filter(chunk => {
        // Check if any selected IP is in this chunk's IP list
        if (!chunk.ips) return false;
        if (!chunk.ips.some(ip => selectedIPSet.has(ip))) return false;

        // Filter by time if overview time filter is active
        if (overviewTimeExtent) {
            const [rangeStart, rangeEnd] = overviewTimeExtent;
            if (chunk.end < rangeStart || chunk.start > rangeEnd) {
                return false;
            }
        }

        return true;
    });
}

/**
 * Load flows from chunks asynchronously with progress reporting.
 * @param {Object} options
 * @param {Array} options.matchingChunks - Chunks to load
 * @param {string} options.basePath - Base path for chunk files
 * @param {string} options.format - Data format ('chunked_flows' or 'chunked_flows_by_ip_pair')
 * @param {Function} options.getChunkPath - Function to get chunk path (optional)
 * @param {Set<string>} options.selectedIPSet - Set of selected IPs
 * @param {Array|null} options.overviewTimeExtent - Time extent filter
 * @param {Function} options.onComplete - Callback when loading completes
 */
export async function loadChunkedFlows(options) {
    const {
        matchingChunks,
        basePath,
        format,
        getChunkPath,
        selectedIPSet,
        overviewTimeExtent,
        onComplete
    } = options;

    // Create progress indicator
    const flagStatsContainer = document.getElementById('flagStats');
    const progressId = 'overview-loading-indicator';
    createProgressIndicator(flagStatsContainer, progressId, {
        totalChunks: matchingChunks.length
    });

    const actualFlows = [];

    // Load chunks with periodic yields to keep UI responsive
    for (let i = 0; i < matchingChunks.length; i++) {
        const chunk = matchingChunks[i];

        // Update progress indicator every 10 chunks
        if (i % 10 === 0 || i === matchingChunks.length - 1) {
            updateProgressIndicator(progressId, null, {
                loaded: i + 1,
                total: matchingChunks.length,
                flowCount: actualFlows.length
            });
        }

        // Yield to browser every 10 chunks
        if (i > 0 && i % 10 === 0) {
            await new Promise(resolve => setTimeout(resolve, 0));
        }

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

            const response = await fetch(chunkPath);
            if (!response.ok) {
                console.warn(`[FlowLoader] Failed to load ${chunk.file}: ${response.status}`);
                continue;
            }

            const chunkFlows = await response.json();

            // Filter flows to only include those where BOTH initiator AND responder are in selectedIPs
            // AND within TimeArcs time range if specified
            const filteredChunkFlows = chunkFlows.filter(flow => {
                if (!flow) return false;

                // Filter by IPs first
                if (!selectedIPSet.has(flow.initiator) || !selectedIPSet.has(flow.responder)) {
                    return false;
                }

                // Apply TimeArcs time filter if overviewTimeExtent is set
                if (overviewTimeExtent && overviewTimeExtent.length === 2) {
                    const flowTime = flow.startTime;
                    if (flowTime < overviewTimeExtent[0] || flowTime > overviewTimeExtent[1]) {
                        return false;
                    }
                }

                return true;
            });

            actualFlows.push(...filteredChunkFlows);
            LOG(`Loaded ${chunk.file}: ${chunkFlows.length} total flows, ${filteredChunkFlows.length} matching selected IPs`);
        } catch (err) {
            console.warn(`[FlowLoader] Error loading ${chunk.file}:`, err);
        }
    }

    // Show completion message
    const completeText = `✓ Loaded ${actualFlows.length} flows from ${matchingChunks.length} chunks`;
    showCompletionThenRemove(progressId, completeText, 2000);

    // Call completion callback
    if (onComplete) {
        onComplete(actualFlows);
    }

    return actualFlows;
}

/**
 * Filter regular flows by selected IPs.
 * @param {Array} flows - Array of flow objects
 * @param {Set<string>} selectedIPSet - Set of selected IPs
 * @returns {Array} Filtered flows
 */
export function filterFlowsByIPs(flows, selectedIPSet) {
    if (!Array.isArray(flows)) return [];
    return flows.filter(f =>
        selectedIPSet.has(f.initiator) && selectedIPSet.has(f.responder)
    );
}

/**
 * Main flow loading decision tree.
 * Determines the best loading strategy and returns loaded flows.
 *
 * @param {Object} context - Context object with getters and callbacks
 * @param {Function} context.getState - Get current state object
 * @param {Object} context.flowDataState - Flow metadata (format, chunksMeta, etc.)
 * @param {Object|null} context.adaptiveOverviewLoader - Adaptive loader instance
 * @param {string[]} context.selectedIPs - Selected IP addresses
 * @param {Function} context.refreshAdaptiveOverview - Callback to refresh overview
 * @param {Function} context.updateTcpFlowStats - Callback to update stats
 * @param {Function} context.calculateGroundTruthStats - Callback for ground truth
 * @param {Function} context.sbUpdateGroundTruthStatsUI - Callback for GT UI
 * @param {Object} context.eventColors - Event color mapping
 * @returns {Promise<Object>} { flows, skipSyncUpdates }
 */
export async function loadFlowData(context) {
    const {
        getState,
        flowDataState,
        adaptiveOverviewLoader,
        selectedIPs,
        refreshAdaptiveOverview,
        updateTcpFlowStats,
        calculateGroundTruthStats,
        sbUpdateGroundTruthStatsUI,
        eventColors
    } = context;

    const state = getState();
    const selectedIPSet = new Set(selectedIPs);

    // Case 1: No IPs selected - show no flows
    if (selectedIPs.length === 0) {
        return { flows: [], skipSyncUpdates: false };
    }

    // Case 2: Flow list CSV files available - defer loading until popup opens
    // (Don't load CSVs now - just return empty and let popup load on-demand)
    const flowListLoader = getFlowListLoader();
    if (flowListLoader.isLoaded()) {
        LOG(`[FlowListLoader] Flow list CSV available - will load on-demand when popup opens`);
        console.log(`[FlowListLoader] Deferring CSV load for ${selectedIPs.length} IPs until popup opens`);

        // Use adaptive overview for the overview chart
        if (adaptiveOverviewLoader && flowDataState && flowDataState.hasAdaptiveOverview) {
            (async () => {
                await refreshAdaptiveOverview(selectedIPs);
            })();
        }

        // Return empty flows - they'll be loaded when popup opens
        // Set flag so UI knows flow list is available
        return { flows: [], skipSyncUpdates: false, hasFlowListAvailable: true };
    }

    // Case 2.5: Adaptive overview available but NO flow list - skip bulk chunk loading
    if (adaptiveOverviewLoader && flowDataState && flowDataState.hasAdaptiveOverview) {
        LOG(`[AdaptiveOverview] Skipping bulk chunk loading - using pre-aggregated overview data`);
        console.log(`[AdaptiveOverview] Skipping bulk chunk loading for ${selectedIPs.length} IPs - no flow list available`);

        // Fire and forget async update for overview and stats
        (async () => {
            await refreshAdaptiveOverview(selectedIPs);

            // Update stats to show we're using adaptive mode (no flow list)
            const tcpFlowStats = document.getElementById('tcpFlowStats');
            if (tcpFlowStats) {
                const totalFlows = adaptiveOverviewLoader.index?.total_flows || 0;
                tcpFlowStats.innerHTML = `<span style="color: #28a745;">Adaptive Overview Mode</span><br>
                    <span style="color: #666;">${totalFlows.toLocaleString()} total flows</span><br>
                    <span style="color: #888; font-size: 11px;">Flow list not available (no flow_list files)</span>`;
            }

            // Update ground truth statistics
            const stats = calculateGroundTruthStats(state.flows.groundTruth, selectedIPs, eventColors);
            sbUpdateGroundTruthStatsUI(stats.html, stats.hasMatches);
        })();

        return { flows: [], skipSyncUpdates: true };
    }

    // Case 3: Chunked flows - load from chunks (fallback when adaptive not available)
    if (flowDataState &&
        (flowDataState.format === 'chunked_flows' || flowDataState.format === 'chunked_flows_by_ip_pair') &&
        flowDataState.chunksMeta) {

        LOG(`Loading chunked flow data for selected IPs:`, selectedIPs);

        // Filter chunks to load
        const matchingChunks = filterChunks(
            flowDataState.chunksMeta,
            selectedIPSet,
            null, // no single-resolution flow bins optimization
            state.timearcs.overviewTimeExtent
        );

        console.log(`[LOADING] Found ${matchingChunks.length} chunks involving selected IPs`);
        LOG(`Found ${matchingChunks.length} chunks involving selected IPs`);

        // Start async chunk loading
        loadChunkedFlows({
            matchingChunks,
            basePath: flowDataState.basePath || 'packets_data/attack_flows_day1to5',
            format: flowDataState.format,
            getChunkPath: flowDataState.getChunkPath,
            selectedIPSet,
            overviewTimeExtent: state.timearcs.overviewTimeExtent,
            onComplete: async (loadedFlows) => {
                // Update state with loaded flows
                state.flows.current = loadedFlows;
                LOG(`Loaded ${loadedFlows.length} actual flows from ${matchingChunks.length} matching chunks`);

                // Clear selection and update stats
                state.flows.selectedIds.clear();
                updateTcpFlowStats(loadedFlows);

                // Update ground truth statistics
                const stats = calculateGroundTruthStats(state.flows.groundTruth, selectedIPs, eventColors);
                sbUpdateGroundTruthStatsUI(stats.html, stats.hasMatches);

                // Update overview chart
                await refreshAdaptiveOverview(selectedIPs);
            }
        });

        return { flows: [], skipSyncUpdates: true };
    }

    // Case 4: Regular flows - filter in-memory
    LOG(`Filtering ${state.flows.tcp.length} flows with selected IPs:`, selectedIPs);
    const filtered = filterFlowsByIPs(state.flows.tcp, selectedIPSet);
    LOG(`Filtered to ${filtered.length} flows matching selected IPs`);

    return { flows: filtered, skipSyncUpdates: false };
}
