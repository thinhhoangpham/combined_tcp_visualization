// src/data/adaptive-overview-loader.js
// Adaptive multi-resolution overview data loader for the overview chart
// Loads pre-aggregated flow bins at different resolutions based on visible time range

/**
 * Simple LRU Cache for caching resolution data
 */
class ResolutionCache {
    constructor(maxSize = 5) {
        this.maxSize = maxSize;
        this.cache = new Map();
    }

    get(key) {
        if (!this.cache.has(key)) return undefined;
        // Move to end (most recently used)
        const value = this.cache.get(key);
        this.cache.delete(key);
        this.cache.set(key, value);
        return value;
    }

    set(key, value) {
        if (this.cache.has(key)) {
            this.cache.delete(key);
        } else if (this.cache.size >= this.maxSize) {
            // Evict oldest (first) entry
            const oldest = this.cache.keys().next().value;
            this.cache.delete(oldest);
        }
        this.cache.set(key, value);
    }

    has(key) {
        return this.cache.has(key);
    }

    clear() {
        this.cache.clear();
    }

    get size() {
        return this.cache.size;
    }
}

/**
 * Column definitions matching the pre-aggregated data format
 * These map to the categories used in overview_chart.js
 */
const FLOW_COLUMNS = [
    'graceful',           // Complete handshake + FIN close
    'abortive',           // Complete handshake + RST close
    'ongoing',            // Established but not closed (legacy)
    'open',               // Established and active
    'rst_during_handshake',
    'invalid_ack',
    'invalid_synack',
    'incomplete_no_synack',
    'incomplete_no_ack',
    'unknown_invalid'
];

/**
 * Map column name to category for overview chart compatibility
 */
const COLUMN_TO_CATEGORY = {
    'graceful': { closeType: 'graceful', invalidReason: null },
    'abortive': { closeType: 'abortive', invalidReason: null },
    'ongoing': { closeType: 'ongoing', invalidReason: null },
    'open': { closeType: 'open', invalidReason: null },
    'rst_during_handshake': { closeType: 'invalid', invalidReason: 'rst_during_handshake' },
    'invalid_ack': { closeType: 'invalid', invalidReason: 'invalid_ack' },
    'invalid_synack': { closeType: 'invalid', invalidReason: 'invalid_synack' },
    'incomplete_no_synack': { closeType: 'invalid', invalidReason: 'incomplete_no_synack' },
    'incomplete_no_ack': { closeType: 'invalid', invalidReason: 'incomplete_no_ack' },
    'unknown_invalid': { closeType: 'invalid', invalidReason: 'unknown_invalid' }
};

/**
 * AdaptiveOverviewLoader
 *
 * Manages loading and filtering of pre-aggregated flow bin data at multiple resolutions.
 * Automatically selects the appropriate resolution based on the visible time range.
 *
 * Usage:
 *   const loader = new AdaptiveOverviewLoader(basePath);
 *   await loader.loadIndex();
 *   const data = await loader.getOverviewData(selectedIPs, timeStart, timeEnd);
 */
export class AdaptiveOverviewLoader {
    /**
     * @param {string} basePath - Path to the dataset directory (e.g., 'packets_data/attack_flows_day1to5_v3')
     */
    constructor(basePath) {
        this.basePath = basePath.replace(/\/$/, ''); // Remove trailing slash
        this.index = null;
        this.resolutionCache = new ResolutionCache(5); // Cache up to 5 resolution files
        this.loadingPromises = new Map(); // Prevent duplicate fetches

        // Callbacks for UI updates
        this.onLoadingStart = null;
        this.onLoadingEnd = null;
        this.onResolutionChange = null;

        // Current state
        this.currentResolution = null;
        this.lastTimeRange = null;
    }

    /**
     * Load the resolution index file
     * @returns {Promise<Object>} The index data
     */
    async loadIndex() {
        if (this.index) return this.index;

        const indexPath = `${this.basePath}/indices/flow_bins_index.json`;
        console.log(`[AdaptiveOverview] Loading index from ${indexPath}`);

        try {
            const response = await fetch(indexPath);
            if (!response.ok) {
                throw new Error(`Failed to load index: ${response.status} ${response.statusText}`);
            }
            this.index = await response.json();
            console.log(`[AdaptiveOverview] Index loaded:`, {
                resolutions: Object.keys(this.index.resolutions),
                totalFlows: this.index.total_flows,
                totalPairs: this.index.total_ip_pairs,
                timeRange: this.index.time_range
            });
            return this.index;
        } catch (err) {
            console.error(`[AdaptiveOverview] Failed to load index:`, err);
            throw err;
        }
    }

    /**
     * Select the appropriate resolution based on visible time range
     * @param {number} timeRangeMinutes - Visible time range in minutes
     * @returns {string} Resolution key ('1min' or 'hour')
     */
    selectResolution(timeRangeMinutes) {
        if (!this.index) {
            console.warn('[AdaptiveOverview] Index not loaded, defaulting to hour resolution');
            return 'hour';
        }

        const resolutions = this.index.resolutions;

        // Check each resolution in order of granularity (finest first)
        // Use the resolution thresholds from the index file
        // Skip '10min' resolution - only use '1min' and 'hour'
        for (const [key, config] of Object.entries(resolutions)) {
            if (key === '10min') continue; // Skip 10-minute resolution
            if (config.use_when_range_minutes_lte !== undefined) {
                if (timeRangeMinutes <= config.use_when_range_minutes_lte) {
                    return key;
                }
            }
        }

        // Default to coarsest resolution (hour)
        return 'hour';
    }

    /**
     * Load a specific resolution file
     * @param {string} resolution - Resolution key ('1min', '10min', or 'hour')
     * @returns {Promise<Object>} The resolution data
     */
    async loadResolution(resolution) {
        // Check cache first
        if (this.resolutionCache.has(resolution)) {
            console.log(`[AdaptiveOverview] Using cached ${resolution} data`);
            return this.resolutionCache.get(resolution);
        }

        // Check if already loading
        if (this.loadingPromises.has(resolution)) {
            console.log(`[AdaptiveOverview] Waiting for in-progress ${resolution} load`);
            return this.loadingPromises.get(resolution);
        }

        // Start loading
        const loadPromise = this._fetchResolution(resolution);
        this.loadingPromises.set(resolution, loadPromise);

        try {
            const data = await loadPromise;
            this.resolutionCache.set(resolution, data);
            return data;
        } finally {
            this.loadingPromises.delete(resolution);
        }
    }

    /**
     * Fetch resolution data from server
     * @private
     */
    async _fetchResolution(resolution) {
        if (!this.index) {
            await this.loadIndex();
        }

        const config = this.index.resolutions[resolution];
        if (!config) {
            throw new Error(`Unknown resolution: ${resolution}`);
        }

        const filePath = `${this.basePath}/indices/${config.file}`;
        console.log(`[AdaptiveOverview] Loading ${resolution} data from ${filePath}`);

        if (this.onLoadingStart) this.onLoadingStart(resolution);

        const startTime = performance.now();

        try {
            const response = await fetch(filePath);
            if (!response.ok) {
                throw new Error(`Failed to load ${resolution}: ${response.status}`);
            }

            const data = await response.json();
            const loadTime = performance.now() - startTime;

            console.log(`[AdaptiveOverview] Loaded ${resolution} in ${loadTime.toFixed(0)}ms:`, {
                bins: data.length,
                sizeKB: Math.round(JSON.stringify(data).length / 1024)
            });

            return data;
        } finally {
            if (this.onLoadingEnd) this.onLoadingEnd(resolution);
        }
    }

    /**
     * Get overview data for selected IPs within a time range
     * This is the main API method for the overview chart
     *
     * @param {string[]} selectedIPs - Array of selected IP addresses
     * @param {number} timeStart - Start time in microseconds
     * @param {number} timeEnd - End time in microseconds
     * @param {Object} options - Additional options
     * @param {number} options.targetBinCount - Target number of bins for display (default: 100)
     * @returns {Promise<Object>} Overview data with bins and metadata
     */
    async getOverviewData(selectedIPs, timeStart, timeEnd, options = {}) {
        const { targetBinCount = 100 } = options;

        // Calculate time range in minutes
        const timeRangeUs = timeEnd - timeStart;
        const timeRangeMinutes = timeRangeUs / 60_000_000;

        // Select appropriate resolution
        const resolution = this.selectResolution(timeRangeMinutes);

        // Track resolution changes
        if (resolution !== this.currentResolution) {
            const oldResolution = this.currentResolution;
            console.log(`[AdaptiveOverview] Resolution change: ${oldResolution} → ${resolution}`);
            this.currentResolution = resolution;
            if (this.onResolutionChange) {
                // Pass the time range so callback can use it for display
                this.onResolutionChange(resolution, oldResolution, { timeStart, timeEnd, timeRangeUs });
            }
        }

        // Load resolution data
        const data = await this.loadResolution(resolution);
        const config = this.index.resolutions[resolution];
        const binWidthUs = config.bin_width_us;

        // Build set of selected IP pairs
        const selectedPairs = this._buildSelectedPairs(selectedIPs);

        // Filter and aggregate bins
        const aggregatedBins = this._aggregateBins(
            data,
            selectedPairs,
            timeStart,
            timeEnd,
            binWidthUs
        );

        // Use bins as-is without rebinning
        const displayBins = aggregatedBins;

        console.log(`[AdaptiveOverview] getOverviewData:`, {
            resolution,
            selectedIPs: selectedIPs.length,
            selectedPairs: selectedPairs.size,
            rawBins: aggregatedBins.length,
            displayBins: displayBins.length,
            timeRangeMinutes: timeRangeMinutes.toFixed(1)
        });

        return {
            resolution,
            binWidthUs,
            bins: displayBins,
            columns: FLOW_COLUMNS,
            timeRange: { start: timeStart, end: timeEnd },
            metadata: {
                rawBinCount: aggregatedBins.length,
                displayBinCount: displayBins.length,
                selectedPairCount: selectedPairs.size
            }
        };
    }

    /**
     * Build set of IP pair keys from selected IPs
     * @private
     */
    _buildSelectedPairs(selectedIPs) {
        const pairs = new Set();

        if (!selectedIPs || selectedIPs.length === 0) {
            return pairs;
        }

        // Generate all pair combinations (sorted alphabetically for canonical form)
        const sortedIPs = [...selectedIPs].sort();

        for (let i = 0; i < sortedIPs.length; i++) {
            for (let j = i + 1; j < sortedIPs.length; j++) {
                pairs.add(`${sortedIPs[i]}<->${sortedIPs[j]}`);
            }
        }

        // Also add single-IP pairs (for filtering data that includes any selected IP)
        // This handles the case where we want all flows involving selected IPs
        for (const ip of selectedIPs) {
            pairs.add(ip);
        }

        return pairs;
    }

    /**
     * Aggregate bins from resolution data for selected IP pairs
     * @private
     */
    _aggregateBins(data, selectedPairs, timeStart, timeEnd, binWidthUs) {
        const result = [];

        // Handle array format (v2 style - array of bin objects)
        if (Array.isArray(data)) {
            for (const bin of data) {
                // Skip bins outside time range
                if (bin.end < timeStart || bin.start > timeEnd) continue;

                const aggregated = this._aggregateBinFlows(bin.flows_by_ip_pair, selectedPairs);
                if (aggregated.totalFlows > 0) {
                    result.push({
                        binIndex: bin.bin,
                        start: bin.start,
                        end: bin.end,
                        counts: aggregated.counts,
                        totalFlows: aggregated.totalFlows
                    });
                }
            }
        }
        // Handle object format (v3 style - sparse pairs with bin indices)
        else if (data.pairs && data.meta) {
            const { meta, pairs } = data;
            const dataTimeStart = meta.time_start;

            // Calculate bin range
            const startBin = Math.max(0, Math.floor((timeStart - dataTimeStart) / binWidthUs));
            const endBin = Math.ceil((timeEnd - dataTimeStart) / binWidthUs);

            // Aggregate across selected pairs
            const binAggregates = new Map();

            for (const pairKey of selectedPairs) {
                const pairData = pairs[pairKey];
                if (!pairData) continue;

                for (const [binIdxStr, counts] of Object.entries(pairData)) {
                    const binIdx = parseInt(binIdxStr, 10);
                    if (binIdx < startBin || binIdx > endBin) continue;

                    if (!binAggregates.has(binIdx)) {
                        binAggregates.set(binIdx, new Array(counts.length).fill(0));
                    }

                    const agg = binAggregates.get(binIdx);
                    counts.forEach((c, i) => { agg[i] += c; });
                }
            }

            // Convert to result format
            for (const [binIdx, counts] of binAggregates.entries()) {
                const binStart = dataTimeStart + binIdx * binWidthUs;
                const binEnd = binStart + binWidthUs;

                // Convert array counts to object
                const countsObj = {};
                let total = 0;
                FLOW_COLUMNS.forEach((col, i) => {
                    if (counts[i] > 0) {
                        countsObj[col] = counts[i];
                        total += counts[i];
                    }
                });

                result.push({
                    binIndex: binIdx,
                    start: binStart,
                    end: binEnd,
                    counts: countsObj,
                    totalFlows: total
                });
            }

            // Sort by bin index
            result.sort((a, b) => a.binIndex - b.binIndex);
        }

        return result;
    }

    /**
     * Aggregate flows from a bin's IP pair data
     * @private
     */
    _aggregateBinFlows(flowsByPair, selectedPairs) {
        const counts = {};
        let totalFlows = 0;

        if (!flowsByPair) {
            return { counts, totalFlows };
        }

        // If no pairs selected, aggregate all
        const aggregateAll = selectedPairs.size === 0;

        for (const [pairKey, pairCounts] of Object.entries(flowsByPair)) {
            // Check if this pair matches selection
            if (!aggregateAll) {
                const [ip1, ip2] = pairKey.split('<->');
                const pairMatches = selectedPairs.has(pairKey) ||
                                   selectedPairs.has(ip1) ||
                                   selectedPairs.has(ip2);
                if (!pairMatches) continue;
            }

            // Aggregate counts from this pair
            // Handle v2 format: { graceful: N, abortive: N, invalid: { reason: N }, ongoing: N }
            if (typeof pairCounts.graceful !== 'undefined') {
                counts.graceful = (counts.graceful || 0) + (pairCounts.graceful || 0);
                totalFlows += pairCounts.graceful || 0;
            }
            if (typeof pairCounts.abortive !== 'undefined') {
                counts.abortive = (counts.abortive || 0) + (pairCounts.abortive || 0);
                totalFlows += pairCounts.abortive || 0;
            }
            if (typeof pairCounts.ongoing !== 'undefined') {
                counts.ongoing = (counts.ongoing || 0) + (pairCounts.ongoing || 0);
                totalFlows += pairCounts.ongoing || 0;
            }
            if (typeof pairCounts.open !== 'undefined') {
                counts.open = (counts.open || 0) + (pairCounts.open || 0);
                totalFlows += pairCounts.open || 0;
            }

            // Handle nested invalid reasons
            if (pairCounts.invalid && typeof pairCounts.invalid === 'object') {
                for (const [reason, count] of Object.entries(pairCounts.invalid)) {
                    counts[reason] = (counts[reason] || 0) + count;
                    totalFlows += count;
                }
            }
        }

        return { counts, totalFlows };
    }

    /**
     * Re-bin aggregated data for display when too many bins
     * Uses time-grid-based rebinning to properly handle sparse data
     * @private
     */
    _rebinForDisplay(bins, targetBinCount, timeStart, timeEnd) {
        if (bins.length <= targetBinCount) return bins;
        if (bins.length === 0) return bins;

        // Calculate display bin width based on time range
        const timeRange = timeEnd - timeStart;
        const displayBinWidth = timeRange / targetBinCount;

        // Create a map for the display grid: displayBinIndex -> aggregated counts
        const displayGrid = new Map();

        for (const bin of bins) {
            // Skip bins outside time range
            if (bin.end < timeStart || bin.start > timeEnd) continue;

            // Determine which display bin this data falls into
            const binMidpoint = (bin.start + bin.end) / 2;
            const displayBinIndex = Math.floor((binMidpoint - timeStart) / displayBinWidth);

            // Clamp to valid range
            const clampedIndex = Math.max(0, Math.min(targetBinCount - 1, displayBinIndex));

            if (!displayGrid.has(clampedIndex)) {
                const displayStart = timeStart + clampedIndex * displayBinWidth;
                displayGrid.set(clampedIndex, {
                    binIndex: clampedIndex,
                    start: displayStart,
                    end: displayStart + displayBinWidth,
                    counts: {},
                    totalFlows: 0
                });
            }

            const merged = displayGrid.get(clampedIndex);
            for (const [key, count] of Object.entries(bin.counts)) {
                merged.counts[key] = (merged.counts[key] || 0) + count;
            }
            merged.totalFlows += bin.totalFlows;
        }

        // Convert to sorted array
        const displayBins = Array.from(displayGrid.values())
            .sort((a, b) => a.binIndex - b.binIndex);

        return displayBins;
    }

    /**
     * Convert aggregated bins to synthetic flow objects for overview_chart.js compatibility
     * This creates flow-like objects that can be processed by the existing overview chart
     *
     * @param {Object} overviewData - Data from getOverviewData()
     * @returns {Array} Array of synthetic flow objects
     */
    toSyntheticFlows(overviewData) {
        const flows = [];

        for (const bin of overviewData.bins) {
            const binMidpoint = (bin.start + bin.end) / 2;

            for (const [category, count] of Object.entries(bin.counts)) {
                if (count <= 0) continue;

                const categoryInfo = COLUMN_TO_CATEGORY[category];
                if (!categoryInfo) continue;

                // Create synthetic flow objects (one per count for accurate binning)
                // For efficiency, we create a single object with a count property
                // that overview_chart can expand if needed
                flows.push({
                    startTime: binMidpoint,
                    closeType: categoryInfo.closeType,
                    invalidReason: categoryInfo.invalidReason,
                    state: categoryInfo.closeType === 'invalid' ? 'invalid' :
                           categoryInfo.closeType === 'open' ? 'established' : null,
                    establishmentComplete: categoryInfo.closeType === 'open',
                    _synthetic: true,
                    _count: count,
                    _binIndex: bin.binIndex
                });
            }
        }

        return flows;
    }

    /**
     * Expand synthetic flows to individual flow objects
     * Use this if overview_chart.js needs actual individual flow objects
     *
     * @param {Array} syntheticFlows - Flows from toSyntheticFlows()
     * @returns {Array} Expanded array with one object per flow
     */
    expandSyntheticFlows(syntheticFlows) {
        const expanded = [];

        for (const flow of syntheticFlows) {
            const count = flow._count || 1;

            // Create individual flow objects
            for (let i = 0; i < count; i++) {
                expanded.push({
                    startTime: flow.startTime,
                    closeType: flow.closeType,
                    invalidReason: flow.invalidReason,
                    state: flow.state,
                    establishmentComplete: flow.establishmentComplete,
                    _synthetic: true
                });
            }
        }

        return expanded;
    }

    /**
     * Get time extent from loaded index
     * @returns {[number, number]|null} Time extent [start, end] in microseconds
     */
    getTimeExtent() {
        if (!this.index || !this.index.time_range) return null;
        return [this.index.time_range.start_us, this.index.time_range.end_us];
    }

    /**
     * Get statistics about the loaded data
     * @returns {Object} Statistics
     */
    getStats() {
        return {
            indexLoaded: !!this.index,
            cachedResolutions: [...this.resolutionCache.cache.keys()],
            currentResolution: this.currentResolution,
            totalFlows: this.index?.total_flows || 0,
            totalPairs: this.index?.total_ip_pairs || 0
        };
    }

    /**
     * Clear all cached data
     */
    clear() {
        this.resolutionCache.clear();
        this.loadingPromises.clear();
        this.currentResolution = null;
        this.lastTimeRange = null;
    }

    /**
     * Prefetch a resolution in the background
     * @param {string} resolution - Resolution to prefetch
     */
    prefetch(resolution) {
        if (this.resolutionCache.has(resolution)) return;
        if (this.loadingPromises.has(resolution)) return;

        console.log(`[AdaptiveOverview] Prefetching ${resolution}`);
        this.loadResolution(resolution).catch(err => {
            console.warn(`[AdaptiveOverview] Prefetch failed for ${resolution}:`, err);
        });
    }
}

// Export column definitions for external use
export { FLOW_COLUMNS, COLUMN_TO_CATEGORY };

// Export singleton factory
let _instance = null;

/**
 * Get or create the adaptive overview loader instance
 * @param {string} basePath - Path to dataset (required on first call)
 * @returns {AdaptiveOverviewLoader}
 */
export function getAdaptiveOverviewLoader(basePath) {
    if (!_instance && basePath) {
        _instance = new AdaptiveOverviewLoader(basePath);
    }
    return _instance;
}

/**
 * Reset the singleton instance (useful for testing or changing datasets)
 */
export function resetAdaptiveOverviewLoader() {
    if (_instance) {
        _instance.clear();
        _instance = null;
    }
}
