// src/interaction/timearcsZoomHandler.js
// Zoom handler for TimeArcs visualization

import { formatDuration } from '../utils/formatters.js';
import { RADIUS_MIN, RADIUS_MAX } from '../config/constants.js';

// Module-level timeout references for debouncing
let zoomTimeout = null;
let handshakeTimeout = null;

/**
 * Create a duration label updater function.
 *
 * @param {Object} context - Context with getters
 * @param {Function} context.getXScale - Get current xScale
 * @param {Object} context.bottomOverlayDurationLabel - D3 selection for label
 * @returns {Function} updater function
 */
export function createDurationLabelUpdater(context) {
    const { getXScale, bottomOverlayDurationLabel } = context;

    return function updateZoomDurationLabel() {
        const xScale = getXScale();
        if (!bottomOverlayDurationLabel || !xScale) return;

        try {
            const domain = xScale.domain();
            const durUs = Math.max(0, Math.floor(domain[1]) - Math.floor(domain[0]));
            const label = formatDuration(durUs);
            const center = xScale((domain[0] + domain[1]) / 2);
            bottomOverlayDurationLabel.attr('x', center).text(label);
        } catch (_) { /* ignore */ }
    };
}

/**
 * Create the TimeArcs zoom handler function.
 *
 * @param {Object} context - Context object with getters and external references
 * @param {Object} context.d3 - D3 library reference
 * @param {Function} context.getXScale - Get current xScale
 * @param {Function} context.getState - Get current state object
 * @param {Function} context.getTimeExtent - Get data time extent
 * @param {number} context.width - Chart width
 * @param {Object} context.fullDomainLayer - D3 selection for full domain layer
 * @param {Object} context.dynamicLayer - D3 selection for dynamic layer
 * @param {Object} context.mainGroup - D3 selection for main group
 * @param {Object} context.bottomOverlayAxisGroup - D3 selection for axis group
 * @param {Object} context.bottomOverlayDurationLabel - D3 selection for duration label
 * @param {Function} context.getFullDomainBinsCache - Get current cache
 * @param {Function} context.setFullDomainBinsCache - Set cache
 * @param {Function} context.getIsHardResetInProgress - Get hard reset flag
 * @param {Function} context.setIsHardResetInProgress - Set hard reset flag
 * @param {Function} context.xAxis - X axis generator
 * @param {Function} context.updateBrushFromZoom - Sync brush with zoom
 * @param {Function} context.updateZoomDurationLabel - Update duration label
 * @param {Function} context.updateZoomIndicator - Update zoom indicator UI
 * @param {Function} context.getResolutionForVisibleRange - Get resolution for range
 * @param {Function} context.renderFlowDetailViewZoomed - Render flow detail
 * @param {Function} context.drawSelectedFlowArcs - Draw flow arcs
 * @param {Function} context.drawGroundTruthBoxes - Draw ground truth
 * @param {Function} context.createSmartTickFormatter - Create tick formatter
 * @param {Function} context.getVisiblePackets - Filter visible packets
 * @param {Function} context.buildSelectedFlowKeySet - Build flow key set
 * @param {Function} context.makeConnectionKey - Create connection key
 * @param {Function} context.findIPPosition - Find IP y position
 * @param {Function} context.getFlagType - Get flag type for packet
 * @param {Function} context.renderMarksForLayer - Render marks
 * @param {Function} context.getGlobalMaxBinCount - Get global max bin count
 * @param {Function} context.getFlagCounts - Get flag counts map
 * @param {Function} context.getMultiResData - Get multi-resolution data (may be null)
 * @param {Function} context.isMultiResAvailable - Check if multi-res available (may be null)
 * @param {Function} context.getUseMultiRes - Get useMultiRes flag
 * @param {Function} context.setCurrentResolutionLevel - Set current resolution
 * @param {Function} context.logCatchError - Error logger
 * @returns {Function} Zoom event handler
 */
export function createTimeArcsZoomHandler(context) {
    const {
        d3,
        getXScale,
        getState,
        getTimeExtent,
        width,
        fullDomainLayer,
        dynamicLayer,
        mainGroup,
        bottomOverlayAxisGroup,
        bottomOverlayDurationLabel,
        getFullDomainBinsCache,
        setFullDomainBinsCache,
        getIsHardResetInProgress,
        setIsHardResetInProgress,
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
        renderMarksForLayer,
        getGlobalMaxBinCount,
        getFlagCounts,
        getMultiResData,
        isMultiResAvailable,
        getUseMultiRes,
        setCurrentResolutionLevel,
        logCatchError
    } = context;

    return function zoomed({ transform, sourceEvent }) {
        const xScale = getXScale();
        const state = getState();
        const timeExtent = getTimeExtent();

        // Handle flow detail mode separately - don't trigger normal packet binning
        if (state.flowDetail.mode && state.flowDetail.packets.length > 0) {
            // Update xScale for flow detail view
            if (sourceEvent && sourceEvent.type === 'wheel' && sourceEvent.deltaX !== 0) {
                const panAmount = sourceEvent.deltaX * 0.5;
                const currentDomain = xScale.domain();
                const domainRange = currentDomain[1] - currentDomain[0];
                const panRatio = panAmount / width;
                const panOffset = domainRange * panRatio;
                xScale.domain([currentDomain[0] - panOffset, currentDomain[1] - panOffset]);
            } else {
                // For flow detail mode, use the flow's time extent as base
                const flowTimeExtent = d3.extent(state.flowDetail.packets, d => d.timestamp);
                const padding = Math.max(50000, (flowTimeExtent[1] - flowTimeExtent[0]) * 0.1);
                const baseExtent = [flowTimeExtent[0] - padding, flowTimeExtent[1] + padding];
                const newXScale = transform.rescaleX(
                    d3.scaleLinear().domain(baseExtent).range([0, width])
                );
                xScale.domain(newXScale.domain());
            }

            // Update axis
            if (bottomOverlayAxisGroup) {
                bottomOverlayAxisGroup.call(
                    d3.axisBottom(xScale).tickFormat(createSmartTickFormatter(xScale.domain()))
                );
            }

            // Update brush and duration label
            try {
                window.__arc_x_domain__ = xScale.domain();
                updateBrushFromZoom();
            } catch (e) { logCatchError('updateBrushFromZoom', e); }
            try { updateZoomDurationLabel(); } catch (e) { logCatchError('updateZoomDurationLabel', e); }

            // Re-render flow detail view with new scale
            renderFlowDetailViewZoomed();
            return; // Don't continue with normal zoom handling
        }

        // Normal zoom handling
        if (sourceEvent && sourceEvent.type === 'wheel' && sourceEvent.deltaX !== 0) {
            const panAmount = sourceEvent.deltaX * 0.5;
            const currentDomain = xScale.domain();
            const domainRange = currentDomain[1] - currentDomain[0];
            const panRatio = panAmount / width;
            const panOffset = domainRange * panRatio;
            xScale.domain([currentDomain[0] - panOffset, currentDomain[1] - panOffset]);
        } else {
            const newXScale = transform.rescaleX(
                d3.scaleLinear().domain(timeExtent).range([0, width])
            );
            xScale.domain(newXScale.domain());
        }

        // Floor domain values
        const currentDomain = xScale.domain();
        xScale.domain([Math.floor(currentDomain[0]), Math.floor(currentDomain[1])]);

        // Update intended zoom domain (preserves zoom state across operations)
        state.timearcs.intendedZoomDomain = xScale.domain().slice();

        const flowsFilteringActiveImmediate = (
            state.ui.showTcpFlows &&
            state.flows.selectedIds.size > 0 &&
            state.flows.tcp.length > 0
        );
        const atFullDomainImmediate = (
            Math.floor(xScale.domain()[0]) <= Math.floor(timeExtent[0]) &&
            Math.floor(xScale.domain()[1]) >= Math.floor(timeExtent[1])
        );

        // Update bottom overlay axis
        try {
            if (bottomOverlayAxisGroup) {
                bottomOverlayAxisGroup.call(xAxis);
            }
        } catch (e) { logCatchError('bottomOverlayAxisGroup.call', e); }

        try { window.__arc_x_domain__ = xScale.domain(); } catch (e) { logCatchError('setArcXDomain', e); }
        updateBrushFromZoom();
        try { updateZoomDurationLabel(); } catch (e) { logCatchError('updateZoomDurationLabel', e); }

        // Update zoom indicator immediately
        try {
            const domain = xScale.domain();
            const visibleRangeUsImmediate = domain[1] - domain[0];
            if (visibleRangeUsImmediate > 0) {
                const resolutionImmediate = getResolutionForVisibleRange(visibleRangeUsImmediate);
                updateZoomIndicator(visibleRangeUsImmediate, resolutionImmediate, 0);
            }
        } catch (e) { logCatchError('updateZoomIndicator', e); }

        const isHardResetInProgress = getIsHardResetInProgress();
        const fullDomainBinsCache = getFullDomainBinsCache();

        // Early return if at full domain with cached data
        if ((isHardResetInProgress || (atFullDomainImmediate && !flowsFilteringActiveImmediate)) &&
            !flowsFilteringActiveImmediate && fullDomainLayer && fullDomainBinsCache.data.length > 0) {
            if (fullDomainLayer) fullDomainLayer.style('display', null);
            if (dynamicLayer) dynamicLayer.style('display', 'none');
            try {
                mainGroup.selectAll('.direction-dot').style('display', 'block').style('opacity', 0.5);
            } catch (e) { logCatchError('directionDotStyle', e); }
            clearTimeout(zoomTimeout);
            clearTimeout(handshakeTimeout);
            setIsHardResetInProgress(false);
            return;
        }

        // Redraw flow arcs on debounce
        if (state.ui.showTcpFlows && state.flows.tcp.length > 0 && state.flows.selectedIds.size > 0) {
            clearTimeout(handshakeTimeout);
            handshakeTimeout = setTimeout(() => { drawSelectedFlowArcs(); }, 8);
        }

        // Redraw ground truth boxes
        if (state.ui.showGroundTruth) {
            const selectedIPs = Array.from(
                document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')
            ).map(cb => cb.value);
            drawGroundTruthBoxes(selectedIPs);
        }

        // Debounced data loading and rendering
        clearTimeout(zoomTimeout);
        zoomTimeout = setTimeout(async () => {
            const flowsFilteringActive = (
                state.ui.showTcpFlows &&
                state.flows.selectedIds.size > 0 &&
                state.flows.tcp.length > 0
            );
            const atFullDomain = (
                Math.floor(xScale.domain()[0]) <= Math.floor(timeExtent[0]) &&
                Math.floor(xScale.domain()[1]) >= Math.floor(timeExtent[1])
            );

            const currentCache = getFullDomainBinsCache();

            // Return to cached full domain view if applicable
            if (atFullDomain && !flowsFilteringActive && fullDomainLayer && currentCache.data.length > 0) {
                fullDomainLayer.style('display', null);
                if (dynamicLayer) dynamicLayer.style('display', 'none');
                try { updateZoomDurationLabel(); } catch (e) { logCatchError('updateZoomDurationLabel', e); }
                const visibleRangeUsFull = xScale.domain()[1] - xScale.domain()[0];
                const resolutionFull = getResolutionForVisibleRange(visibleRangeUsFull);
                updateZoomIndicator(visibleRangeUsFull, resolutionFull, currentCache.data.length);
                return;
            }

            // Switch to dynamic layer
            if (fullDomainLayer) fullDomainLayer.style('display', 'none');
            if (dynamicLayer) dynamicLayer.style('display', null);

            let binnedPackets;
            let usedMultiRes = false;
            const useMultiRes = getUseMultiRes();
            const multiResDataFn = getMultiResData;
            const multiResAvailableFn = isMultiResAvailable;

            // Try multi-resolution data first
            if (useMultiRes && multiResDataFn && multiResAvailableFn && multiResAvailableFn()) {
                try {
                    const multiResResult = await multiResDataFn(xScale);
                    if (multiResResult.data && multiResResult.data.length > 0) {
                        setCurrentResolutionLevel(multiResResult.resolution);
                        usedMultiRes = true;

                        // Process multi-resolution data
                        let processedData = multiResResult.data.map(d => ({
                            ...d,
                            yPos: findIPPosition(
                                d.src_ip, d.src_ip, d.dst_ip,
                                state.layout.pairs, state.layout.ipPositions
                            ),
                            binCenter: d.bin_start
                                ? (d.bin_start + (d.bin_end - d.bin_start) / 2)
                                : d.timestamp,
                            flagType: d.flagType || d.flag_type || 'OTHER',
                            binned: multiResResult.preBinned ? (d.binned !== false) : false,
                            count: d.count || 1,
                            originalPackets: d.originalPackets || [d]
                        }));

                        // Apply flow filtering if active
                        if (flowsFilteringActive) {
                            const selectedKeys = buildSelectedFlowKeySet();
                            processedData = processedData.filter(packet => {
                                if (!packet || !packet.src_ip || !packet.dst_ip) return false;
                                const key = makeConnectionKey(
                                    packet.src_ip, packet.src_port || 0,
                                    packet.dst_ip, packet.dst_port || 0
                                );
                                return selectedKeys.has(key);
                            });
                        }

                        binnedPackets = processedData;
                        const visibleRangeUs = xScale.domain()[1] - xScale.domain()[0];
                        updateZoomIndicator(visibleRangeUs, multiResResult.resolution, binnedPackets.length);
                    }
                } catch (err) {
                    console.warn('Multi-res data loading failed, falling back:', err);
                    usedMultiRes = false;
                }
            }

            // Fall back to filtered data
            if (!usedMultiRes) {
                setCurrentResolutionLevel(null);
                const visibleRangeUs = xScale.domain()[1] - xScale.domain()[0];

                if (atFullDomain && !flowsFilteringActive &&
                    currentCache.version === state.data.version &&
                    currentCache.data.length > 0) {
                    binnedPackets = currentCache.data;
                } else {
                    let visiblePackets = getVisiblePackets(state.data.filtered, xScale);

                    if (flowsFilteringActive) {
                        const selectedKeys = buildSelectedFlowKeySet();
                        visiblePackets = visiblePackets.filter(packet => {
                            if (!packet || !packet.src_ip || !packet.dst_ip) return false;
                            const key = makeConnectionKey(
                                packet.src_ip, packet.src_port || 0,
                                packet.dst_ip, packet.dst_port || 0
                            );
                            return selectedKeys.has(key);
                        });
                    }

                    if (!visiblePackets || visiblePackets.length === 0) {
                        if (dynamicLayer) dynamicLayer.selectAll('.direction-dot').remove();
                        const resolutionEmpty = getResolutionForVisibleRange(visibleRangeUs);
                        updateZoomIndicator(visibleRangeUs, resolutionEmpty, 0);
                        return;
                    }

                    // Add y positions (data is pre-binned)
                    binnedPackets = visiblePackets.map(d => ({
                        ...d,
                        yPos: findIPPosition(
                            d.src_ip, d.src_ip, d.dst_ip,
                            state.layout.pairs, state.layout.ipPositions
                        ),
                        binCenter: d.bin_start
                            ? (d.bin_start + (d.bin_end - d.bin_start) / 2)
                            : d.timestamp,
                        flagType: d.flagType || d.flag_type || 'OTHER',
                        binned: d.binned !== false,
                        count: d.count || 1,
                        originalPackets: d.originalPackets || [d]
                    }));

                    if (atFullDomain && !flowsFilteringActive) {
                        setFullDomainBinsCache({
                            version: state.data.version,
                            data: binnedPackets,
                            binSize: null,
                            sorted: false
                        });
                    }
                }

                const fallbackResolution = getResolutionForVisibleRange(visibleRangeUs);
                updateZoomIndicator(visibleRangeUs, fallbackResolution, binnedPackets.length);
            }

            // Sort if not already sorted in cache
            const updatedCache = getFullDomainBinsCache();
            if (!(atFullDomain && !flowsFilteringActive && updatedCache.sorted)) {
                const flagCounts = getFlagCounts();
                binnedPackets.sort((a, b) => {
                    const flagA = getFlagType(a);
                    const flagB = getFlagType(b);
                    const countA = flagCounts[flagA] || 0;
                    const countB = flagCounts[flagB] || 0;
                    if (countA !== countB) return countB - countA;
                    return a.timestamp - b.timestamp;
                });
                if (atFullDomain && !flowsFilteringActive) {
                    const cache = getFullDomainBinsCache();
                    cache.sorted = true;
                    setFullDomainBinsCache(cache);
                }
            }

            try { updateZoomDurationLabel(); } catch (e) { logCatchError('updateZoomDurationLabel', e); }

            const globalMaxBinCount = getGlobalMaxBinCount();
            const rScale = d3.scaleSqrt()
                .domain([1, Math.max(1, globalMaxBinCount)])
                .range([RADIUS_MIN, RADIUS_MAX]);

            renderMarksForLayer(dynamicLayer, binnedPackets, rScale);
        }, 50); // Debounce delay
    };
}

/**
 * Clear any pending zoom timeouts (for cleanup).
 */
export function clearZoomTimeouts() {
    clearTimeout(zoomTimeout);
    clearTimeout(handshakeTimeout);
}
