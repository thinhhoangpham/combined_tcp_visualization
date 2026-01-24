// src/data/flow-list-loader.js
// Loads flow_list CSV files for flow list popup (summary data without packet arrays)

/**
 * Parse a CSV row into a flow object
 * CSV columns: src,dst,st,et,p,sp,dp,ct,ir
 */
function parseFlowRow(row, index) {
    const [src, dst, st, et, p, sp, dp, ct, ir] = row;
    return {
        id: index,
        initiator: src,
        responder: dst,
        startTime: parseInt(st, 10),
        endTime: parseInt(et, 10),
        totalPackets: parseInt(p, 10),
        initiatorPort: parseInt(sp, 10) || 0,
        responderPort: parseInt(dp, 10) || 0,
        closeType: ct || '',
        invalidReason: ir || '',
        // Derived fields for compatibility
        totalBytes: 0,  // Not available in summary
        state: ct === 'invalid' ? 'invalid' : (ct ? 'closed' : 'unknown'),
        establishmentComplete: ct === 'graceful' || ct === 'abortive'
    };
}

/**
 * Parse CSV text into array of flow objects
 */
function parseFlowCSV(csvText) {
    const lines = csvText.trim().split('\n');
    if (lines.length < 2) return [];

    // Skip header row
    const flows = [];
    for (let i = 1; i < lines.length; i++) {
        const row = lines[i].split(',');
        if (row.length >= 5) {  // At least src,dst,st,et,p
            flows.push(parseFlowRow(row, i - 1));
        }
    }
    return flows;
}

/**
 * Flow list loader - manages loading and filtering of flow summaries
 * Used when chunk files are not available (e.g., GitHub deployment)
 */
export class FlowListLoader {
    constructor() {
        this.index = null;
        this.pairsByKey = null;  // Map of ip_pair -> { file, count, loaded, flows }
        this.metadata = null;
        this.basePath = null;
        this.loaded = false;
        this.loading = false;
        this.loadPromise = null;
    }

    /**
     * Load flow_list index.json from the specified base path
     * @param {string} basePath - Base path to the data directory
     * @returns {Promise<boolean>} - True if loaded successfully
     */
    async load(basePath) {
        if (this.loaded) return true;
        if (this.loading) return this.loadPromise;

        this.loading = true;
        this.basePath = basePath;
        this.loadPromise = this._doLoad(basePath);

        try {
            await this.loadPromise;
            return this.loaded;
        } finally {
            this.loading = false;
        }
    }

    async _doLoad(basePath) {
        const url = `${basePath}/indices/flow_list/index.json`;
        console.log(`[FlowListLoader] Loading ${url}...`);

        try {
            const response = await fetch(url);
            if (!response.ok) {
                console.warn(`[FlowListLoader] index.json not found (${response.status})`);
                return false;
            }

            this.index = await response.json();

            this.metadata = {
                version: this.index.version,
                format: this.index.format,
                columns: this.index.columns,
                totalFlows: this.index.total_flows,
                totalPairs: this.index.total_pairs,
                uniqueIPs: this.index.unique_ips,
                timeRange: this.index.time_range
            };

            // Build lookup by IP pair
            this.pairsByKey = new Map();
            for (const pairInfo of this.index.pairs) {
                this.pairsByKey.set(pairInfo.pair, {
                    file: pairInfo.file,
                    count: pairInfo.count,
                    loaded: false,
                    flows: null
                });
            }

            this.loaded = true;
            console.log(`[FlowListLoader] Index loaded: ${this.index.total_pairs} IP pairs, ${this.index.total_flows.toLocaleString()} total flows`);
            return true;

        } catch (err) {
            console.error('[FlowListLoader] Error loading index.json:', err);
            return false;
        }
    }

    /**
     * Check if flow list index is loaded
     * @returns {boolean}
     */
    isLoaded() {
        return this.loaded;
    }

    /**
     * Get metadata about the loaded flow list
     * @returns {Object|null}
     */
    getMetadata() {
        return this.metadata;
    }

    /**
     * Get time range of all flows
     * @returns {[number, number]|null}
     */
    getTimeRange() {
        if (!this.metadata || !this.metadata.timeRange) return null;
        return [this.metadata.timeRange.start, this.metadata.timeRange.end];
    }

    /**
     * Normalize IP pair key (alphabetically sorted)
     */
    _normalizeIPPair(ip1, ip2) {
        return ip1 < ip2 ? `${ip1}<->${ip2}` : `${ip2}<->${ip1}`;
    }

    /**
     * Get all IP pairs that involve the given IPs
     * @param {string[]} selectedIPs - Array of selected IPs
     * @returns {string[]} Array of IP pair keys
     */
    _getRelevantPairs(selectedIPs) {
        if (!this.pairsByKey) return [];

        const selectedSet = new Set(selectedIPs);
        const relevantPairs = [];

        for (const [pairKey, pairInfo] of this.pairsByKey) {
            // Parse IP pair key: "ip1<->ip2"
            const [ip1, ip2] = pairKey.split('<->');
            // Both IPs must be selected
            if (selectedSet.has(ip1) && selectedSet.has(ip2)) {
                relevantPairs.push(pairKey);
            }
        }

        return relevantPairs;
    }

    /**
     * Load flows for a specific IP pair
     * @param {string} pairKey - IP pair key like "ip1<->ip2"
     * @returns {Promise<Array>} Array of flow objects
     */
    async _loadPairFlows(pairKey) {
        const pairInfo = this.pairsByKey.get(pairKey);
        if (!pairInfo) return [];

        // Return cached if already loaded
        if (pairInfo.loaded && pairInfo.flows) {
            return pairInfo.flows;
        }

        // Load the CSV file
        const url = `${this.basePath}/indices/flow_list/${pairInfo.file}`;
        try {
            const response = await fetch(url);
            if (!response.ok) {
                console.warn(`[FlowListLoader] Failed to load ${pairInfo.file}: ${response.status}`);
                return [];
            }

            const csvText = await response.text();
            const flows = parseFlowCSV(csvText);

            // Cache the result
            pairInfo.loaded = true;
            pairInfo.flows = flows;

            console.log(`[FlowListLoader] Loaded ${flows.length} flows from ${pairInfo.file}`);
            return flows;

        } catch (err) {
            console.error(`[FlowListLoader] Error loading ${pairInfo.file}:`, err);
            return [];
        }
    }

    /**
     * Filter flows by selected IPs
     * Both initiator AND responder must be in the selected set
     * Loads CSV files on-demand for relevant IP pairs
     *
     * @param {string[]} selectedIPs - Array of selected IP addresses
     * @param {[number, number]|null} timeExtent - Optional time filter [start, end]
     * @returns {Promise<Array>} Filtered flows
     */
    async filterByIPs(selectedIPs, timeExtent = null) {
        if (!this.loaded || !this.pairsByKey) return [];
        if (!selectedIPs || selectedIPs.length === 0) return [];

        // Find relevant IP pairs
        const relevantPairs = this._getRelevantPairs(selectedIPs);
        console.log(`[FlowListLoader] Found ${relevantPairs.length} relevant IP pairs for ${selectedIPs.length} selected IPs`);

        if (relevantPairs.length === 0) return [];

        // Load flows for all relevant pairs (in parallel)
        const loadPromises = relevantPairs.map(pairKey => this._loadPairFlows(pairKey));
        const pairFlowArrays = await Promise.all(loadPromises);

        // Flatten and optionally filter by time
        let allFlows = pairFlowArrays.flat();

        if (timeExtent && timeExtent.length === 2) {
            const [start, end] = timeExtent;
            allFlows = allFlows.filter(flow =>
                flow.startTime >= start && flow.startTime <= end
            );
        }

        // Sort by start time
        allFlows.sort((a, b) => a.startTime - b.startTime);

        console.log(`[FlowListLoader] Returning ${allFlows.length} flows`);
        return allFlows;
    }

    /**
     * Get a flow by ID (searches loaded pairs)
     * @param {number|string} id - Flow ID
     * @returns {Object|null} Flow object or null
     */
    getFlowById(id) {
        if (!this.loaded) return null;

        const numId = Number(id);
        for (const pairInfo of this.pairsByKey.values()) {
            if (pairInfo.loaded && pairInfo.flows) {
                const flow = pairInfo.flows.find(f => f.id === numId);
                if (flow) return flow;
            }
        }
        return null;
    }
}

// Singleton instance
let flowListLoaderInstance = null;

/**
 * Get the singleton flow list loader instance
 * @returns {FlowListLoader}
 */
export function getFlowListLoader() {
    if (!flowListLoaderInstance) {
        flowListLoaderInstance = new FlowListLoader();
    }
    return flowListLoaderInstance;
}

/**
 * Try to load flow_list index and return whether it's available
 * @param {string} basePath - Base path to data directory
 * @returns {Promise<boolean>}
 */
export async function tryLoadFlowList(basePath) {
    const loader = getFlowListLoader();
    return await loader.load(basePath);
}
