/**
 * Integration module for folder-based loading with existing visualization
 * Bridges the DataSource (with DuckDB support) with the ip_bar_diagram visualization
 * Now supports CSV-based multi-resolution loading from resolutions/ folder
 */

import { folderLoader } from './folder_loader.js';

// Lazy load optional modules that may fail (DuckDB, etc.)
let dataSource = null;
let resolutionManager = null;
let csvResolutionManager = null;
let RESOLUTION = null;

async function loadOptionalModules() {
    try {
        const dataSourceModule = await import('./src/data/data-source.js');
        dataSource = dataSourceModule.dataSource;
    } catch (err) {
        console.warn('[FolderIntegration] data-source.js not available (DuckDB disabled):', err.message);
    }

    try {
        const resModule = await import('./src/data/resolution-manager.js');
        resolutionManager = resModule.resolutionManager;
    } catch (err) {
        console.warn('[FolderIntegration] resolution-manager.js not available:', err.message);
    }

    try {
        const csvResModule = await import('./src/data/csv-resolution-manager.js');
        csvResolutionManager = csvResModule.csvResolutionManager;
        RESOLUTION = csvResModule.RESOLUTION;
    } catch (err) {
        console.warn('[FolderIntegration] csv-resolution-manager.js not available:', err.message);
    }
}

// Store current state
let currentMode = 'csv'; // 'csv' or 'folder'
let selectedIPs = [];
let currentFlowsIndex = [];
let useMultiResolution = false;
let useCsvMultiRes = false;  // True when using CSV-based resolution files
let chunkedFlowState = null;  // State for chunked_flows format (on-demand loading)

/**
 * Initialize folder integration
 */
export function initFolderIntegration() {
    console.log('Initializing folder integration...');
    
    // Wire up data source radio buttons
    const csvRadio = document.getElementById('dataSourceCSV');
    const folderRadio = document.getElementById('dataSourceFolder');
    const csvSection = document.getElementById('csvSourceSection');
    const folderSection = document.getElementById('folderSourceSection');
    
    csvRadio.addEventListener('change', () => {
        if (csvRadio.checked) {
            currentMode = 'csv';
            csvSection.style.display = 'block';
            folderSection.style.display = 'none';
        }
    });
    
    folderRadio.addEventListener('change', () => {
        if (folderRadio.checked) {
            currentMode = 'folder';
            csvSection.style.display = 'none';
            folderSection.style.display = 'block';
        }
    });
    
    // Wire up separate packet/flow folder buttons
    const openPacketsFolderBtn = document.getElementById('openPacketsFolderBtn');
    const openFlowsFolderBtn = document.getElementById('openFlowsFolderBtn');

    if (openPacketsFolderBtn) {
        openPacketsFolderBtn.addEventListener('click', () => handleOpenFolder('packets'));
    }
    if (openFlowsFolderBtn) {
        openFlowsFolderBtn.addEventListener('click', () => handleOpenFolder('flows'));
    }

    console.log('Folder integration initialized');
}

/**
 * Handle opening a folder - validates format matches the requested mode
 * @param {string} mode - 'packets' or 'flows'
 */
async function handleOpenFolder(mode = 'packets') {
    try {
        showProgress(`Opening ${mode} folder...`, 0);

        const result = await folderLoader.openFolder();

        if (!result.success) {
            hideProgress();
            if (!result.cancelled) {
                alert('Failed to open folder. Please try again.');
            }
            return;
        }

        hideProgress();

        const folderHandle = folderLoader.folderHandle;
        const manifest = result.manifest;
        const hasCsvResolutions = await checkCsvResolutionsAvailable(folderHandle);

        // Validate folder format matches requested mode
        const isFlowFormat = manifest?.format === 'multires_flows' || manifest?.format === 'chunked_flows' || manifest?.format === 'chunked' || manifest?.format === 'chunked_flows_by_ip_pair';
        const isPacketFormat = manifest?.format === 'multires_packets' || (!isFlowFormat && hasCsvResolutions);

        if (mode === 'flows' && !isFlowFormat) {
            alert(`This folder contains packet data, not flow data.\n\nExpected format: multires_flows, chunked_flows, or chunked\nFound format: ${manifest?.format || 'unknown'}\n\nPlease use "Load Packets" button instead.`);
            return;
        }

        if (mode === 'packets' && isFlowFormat) {
            alert(`This folder contains flow data, not packet data.\n\nExpected format: multires_packets\nFound format: ${manifest?.format}\n\nPlease use "Load Flows" button instead.`);
            return;
        }

        // Determine format type for display
        let formatType = mode === 'flows' ? 'Multi-Resolution Flows' : 'Multi-Resolution Packets';

        // Update UI with folder info
        const folderInfo = document.getElementById('folderInfo');
        const countLabel = mode === 'flows' ? 'Flows' : 'Packets';
        const totalCount = mode === 'flows'
            ? result.manifest?.total_flows?.toLocaleString()
            : result.manifest?.total_packets?.toLocaleString();

        folderInfo.innerHTML = `
            <strong>Folder:</strong> ${result.folderName}<br>
            <strong>Format:</strong> ${formatType}<br>
            <strong>${countLabel}:</strong> ${totalCount || 'N/A'}<br>
            <strong>IPs:</strong> ${result.manifest?.unique_ips || 'N/A'}
            <div style="margin-top: 8px;">
                <button id="loadDataBtn" style="padding: 6px 12px; background: #28a745; color: white; border: none; border-radius: 4px; cursor: pointer;">
                    ▶ Load ${mode === 'flows' ? 'Flows' : 'Packets'}
                </button>
            </div>
        `;

        // Wire up load data button with the correct mode
        document.getElementById('loadDataBtn').addEventListener('click', () => {
            if (mode === 'flows') {
                // Choose handler based on format
                if (manifest?.format === 'chunked_flows' || manifest?.format === 'chunked' || manifest?.format === 'chunked_flows_by_ip_pair') {
                    handleChunkedFlowsFolder(result);
                } else {
                    handleFlowMultiResFolder(result);
                }
            } else {
                handleCsvMultiResFolder(result);
            }
        });

        console.log(`[FolderIntegration] Folder opened: ${result.folderName}, mode: ${mode}, format: ${manifest?.format}`);

    } catch (err) {
        hideProgress();
        console.error('Error opening folder:', err);
        alert(`Error opening folder: ${err.message}`);
    }
}

/**
 * Load data from the opened folder
 */
async function loadFolderData(hasCsvResolutions, result) {
    try {
        if (hasCsvResolutions) {
            const manifest = result.manifest;

            // Check for flow-based format (from tcp_flow_detector_multires.py)
            if (manifest?.format === 'multires_flows') {
                console.log('[FolderIntegration] Flow-based multi-resolution format detected!');
                await handleFlowMultiResFolder(result);
                return;
            }

            // Packet-based multi-resolution format
            console.log('[FolderIntegration] Packet-based multi-resolution format detected!');
            await handleCsvMultiResFolder(result);
            return;
        }

        // Standard folder format - load packets.csv if available
        const folderHandle = folderLoader.folderHandle;
        let hasPacketsCsv = false;

        try {
            await folderHandle.getFileHandle('packets.csv');
            hasPacketsCsv = true;
        } catch { /* no packets.csv */ }

        if (!hasPacketsCsv) {
            // Try to load flows index directly without packets.csv
            console.log('[FolderIntegration] No packets.csv found, loading flows index only...');
            showProgress('Loading flows index...', 20);

            try {
                const flowsIndex = await folderLoader.loadFlowsIndex();
                currentFlowsIndex = flowsIndex;

                // Load statistics
                showProgress('Loading statistics...', 60);
                let ipStats = {};
                let flagStats = {};

                try {
                    ipStats = await folderLoader.loadIPStats();
                } catch (e) {
                    console.warn('[FolderIntegration] IP stats not available:', e.message);
                }

                try {
                    flagStats = await folderLoader.loadFlagStats();
                } catch (e) {
                    console.warn('[FolderIntegration] Flag stats not available:', e.message);
                }

                hideProgress();

                // Trigger visualization with flows data (no packets)
                console.log('[FolderIntegration] Triggering visualization with flows-only data...');
                triggerVisualizationFromFolder([], flowsIndex, ipStats, flagStats, result.manifest);
                return;
            } catch (flowErr) {
                hideProgress();
                alert(`No packets.csv or flows_index.json found in folder. Please select a valid data folder.`);
                return;
            }
        }

        // Load packets for visualization
        showProgress('Loading packets...', 10);
        const packets = await folderLoader.loadPackets((progress, current, total) => {
            showProgress(`Loading packets: ${current.toLocaleString()} / ${total.toLocaleString()}`, 10 + (progress * 0.6));
        });

        // Load flows index
        showProgress('Loading flows index...', 70);
        const flowsIndex = await folderLoader.loadFlowsIndex();
        currentFlowsIndex = flowsIndex;

        // Load statistics
        showProgress('Loading statistics...', 80);
        const ipStats = await folderLoader.loadIPStats();
        const flagStats = await folderLoader.loadFlagStats();

        hideProgress();

        // Trigger visualization with loaded data
        console.log('Triggering visualization with folder data...');
        triggerVisualizationFromFolder(packets, flowsIndex, ipStats, flagStats, result.manifest);

    } catch (err) {
        hideProgress();
        console.error('Error loading data:', err);
        alert(`Error loading data: ${err.message}`);
    }
}

/**
 * Check if folder contains CSV-based multi-resolution format
 */
async function checkCsvResolutionsAvailable(folderHandle) {
    try {
        const resDir = await folderHandle.getDirectoryHandle('resolutions');
        // Check for seconds index
        const secondsDir = await resDir.getDirectoryHandle('seconds');
        await secondsDir.getFileHandle('index.json');
        return true;
    } catch {
        return false;
    }
}

/**
 * Handle CSV-based multi-resolution folder loading
 */
async function handleCsvMultiResFolder(result) {
    useCsvMultiRes = true;
    useMultiResolution = true;

    // Ensure optional modules are loaded
    await loadOptionalModules();

    if (!csvResolutionManager) {
        throw new Error('CSV Resolution Manager not available. Check browser console for module loading errors.');
    }

    try {
        // Update UI with folder info
        const folderInfo = document.getElementById('folderInfo');
        folderInfo.innerHTML = `
            <strong>Folder:</strong> ${result.folderName}<br>
            <strong>Format:</strong> Multi-Resolution CSV<br>
            <strong>Packets:</strong> ${result.manifest?.total_packets?.toLocaleString() || 'Loading...'}<br>
            <strong>IPs:</strong> ${result.manifest?.unique_ips || 'Loading...'}
        `;

        // Initialize CSV resolution manager - use folderLoader.folderHandle
        showProgress('Loading resolution index...', 10);
        const secondsData = await csvResolutionManager.init(folderLoader.folderHandle);

        console.log(`[FolderIntegration] Loaded ${secondsData.length} second-level bins`);

        // Update folder info with loaded data
        folderInfo.innerHTML = `
            <strong>Folder:</strong> ${result.folderName}<br>
            <strong>Format:</strong> Multi-Resolution CSV<br>
            <strong>Second bins:</strong> ${secondsData.length.toLocaleString()}<br>
            <strong>Time range:</strong> ${formatTimeRange(csvResolutionManager.timeExtent)}
        `;

        // Extract unique IPs from seconds data
        showProgress('Extracting IP addresses...', 50);
        const uniqueIPs = extractUniqueIPsFromBins(secondsData);
        console.log(`[FolderIntegration] Found ${uniqueIPs.length} unique IPs`);

        hideProgress();

        // Trigger visualization with seconds data (aggregated view)
        console.log('[FolderIntegration] Triggering visualization with multi-resolution data...');
        triggerMultiResVisualization(secondsData, uniqueIPs, result.manifest);

    } catch (err) {
        hideProgress();
        console.error('[FolderIntegration] Error loading multi-resolution data:', err);
        alert(`Error loading multi-resolution data: ${err.message}`);
    }
}

// Store for on-demand flow loading
let flowResolutionState = null;

/**
 * Handle flow-based multi-resolution folder (from tcp_flow_detector_multires.py)
 * Only loads overview (seconds) data initially - flows are loaded on-demand
 */
async function handleFlowMultiResFolder(result) {
    showProgress('Loading overview data...', 10);

    const folderHandle = folderLoader.folderHandle;
    const resDir = await folderHandle.getDirectoryHandle('resolutions');

    // Load seconds data for timeline overview
    const secDir = await resDir.getDirectoryHandle('seconds');
    const dataFile = await secDir.getFileHandle('data.csv');
    const secondsCSV = await (await dataFile.getFile()).text();
    const secondsBins = parseFlowSecondsCSV(secondsCSV);

    showProgress('Loading flow index...', 50);

    // Load raw flow index (metadata only, not actual flows)
    const rawDir = await resDir.getDirectoryHandle('raw');
    const indexFile = await rawDir.getFileHandle('index.json');
    const rawIndex = JSON.parse(await (await indexFile.getFile()).text());

    // Store state for on-demand loading
    flowResolutionState = {
        folderHandle,
        resDir,
        rawDir,
        rawIndex,
        manifest: result.manifest,
        flowCache: new Map(),  // Cache loaded chunks
        timeExtent: [rawIndex.time_range.start, rawIndex.time_range.end]
    };

    showProgress('Extracting IPs from manifest...', 80);

    // Get unique IP count from manifest (don't load all flows just for IPs)
    const uniqueIPCount = result.manifest?.unique_ips || 0;

    hideProgress();

    // Dispatch a separate event for flow data that doesn't reset visualization
    // This preserves current IP selection and packet data
    const event = new CustomEvent('flowDataLoaded', {
        detail: {
            overviewBins: secondsBins,
            manifest: result.manifest,
            flowResolutionState: flowResolutionState,
            loadFlowsForTimeRange: loadFlowsForTimeRange,
            totalFlows: rawIndex.total_count,
            timeExtent: flowResolutionState.timeExtent
        }
    });
    document.dispatchEvent(event);

    console.log(`[FolderIntegration] Flow data loaded: ${secondsBins.length} overview bins, ${rawIndex.total_count} flows available on-demand`);
}

/**
 * Handle chunked flows folder (from tcp_data_loader_streaming.py v2.1)
 * Loads flows from flows/flows_index.json and flows/chunk_*.json
 */
async function handleChunkedFlowsFolder(result) {
    showProgress('Loading flows index...', 10);

    const folderHandle = folderLoader.folderHandle;

    // Check if folder handle is still valid
    if (!folderHandle) {
        hideProgress();
        alert('Folder handle is no longer valid. Please select the folder again.');
        return;
    }

    try {
        // Verify/request permission to read the folder
        let permission = 'prompt';
        try {
            permission = await folderHandle.queryPermission({ mode: 'read' });
        } catch (e) {
            console.warn('[FolderIntegration] queryPermission failed:', e.message);
        }

        console.log(`[FolderIntegration] Current permission: ${permission}`);

        if (permission !== 'granted') {
            try {
                permission = await folderHandle.requestPermission({ mode: 'read' });
            } catch (e) {
                console.warn('[FolderIntegration] requestPermission failed:', e.message);
            }

            if (permission !== 'granted') {
                throw new Error('Permission to read folder was denied. Please try again and grant access.');
            }
        }

        // Load flows directory
        let flowsDir;
        try {
            flowsDir = await folderHandle.getDirectoryHandle('flows');
            console.log('[FolderIntegration] Got flows/ directory handle');
        } catch (dirErr) {
            console.error('[FolderIntegration] Cannot access flows/ directory:', dirErr);
            throw new Error(`Cannot access 'flows/' directory. Make sure this folder was created by tcp_data_loader_streaming.py and contains a 'flows/' subdirectory.\n\nError: ${dirErr.message}`);
        }

        // Load chunks metadata (small file with time ranges and category counts per chunk)
        showProgress('Loading chunks metadata...', 30);
        let chunksMeta = [];
        let isV3Format = false;  // v3 uses pairs_meta.json with flows organized by IP pair

        // Check for v3 format (chunked_flows_by_ip_pair) first
        const manifestFormat = result.manifest?.format;
        if (manifestFormat === 'chunked_flows_by_ip_pair') {
            try {
                const pairsMetaFile = await flowsDir.getFileHandle('pairs_meta.json');
                const pairsMetaContent = await (await pairsMetaFile.getFile()).text();
                const pairsMeta = JSON.parse(pairsMetaContent);
                isV3Format = true;

                // Flatten pairs_meta into chunksMeta format for unified handling
                // Each pair has: pair_folder, ips, chunks (array with file, start, end, count, etc.)
                for (const pair of pairsMeta) {
                    for (const chunk of (pair.chunks || [])) {
                        chunksMeta.push({
                            file: `by_pair/${pair.pair_folder}/${chunk.file}`,
                            start: chunk.start,
                            end: chunk.end,
                            count: chunk.count,
                            graceful: chunk.graceful || 0,
                            abortive: chunk.abortive || 0,
                            invalid: chunk.invalid || 0,
                            ongoing: chunk.ongoing || 0,
                            ips: pair.ips,
                            ipPair: pair.pair_folder
                        });
                    }
                }
                console.log(`[FolderIntegration] v3 format: Loaded ${pairsMeta.length} IP pairs, ${chunksMeta.length} total chunks`);
            } catch (v3Err) {
                console.warn('[FolderIntegration] pairs_meta.json not found:', v3Err.message);
            }
        }

        // If not v3 or v3 failed, try v2 format (chunks_meta.json)
        if (!isV3Format || chunksMeta.length === 0) {
            try {
                const metaFile = await flowsDir.getFileHandle('chunks_meta.json');
                const metaContent = await (await metaFile.getFile()).text();
                chunksMeta = JSON.parse(metaContent);
                console.log(`[FolderIntegration] v2 format: Loaded metadata for ${chunksMeta.length} chunks`);
            } catch (metaErr) {
                console.warn('[FolderIntegration] chunks_meta.json not found, will scan chunks:', metaErr.message);
                // Fallback: scan chunk files (slower, for old data)
                try {
                    for await (const entry of flowsDir.values()) {
                        if (entry.kind === 'file' && entry.name.startsWith('chunk_') && entry.name.endsWith('.json')) {
                            chunksMeta.push({ file: entry.name });
                        }
                    }
                    chunksMeta.sort((a, b) => a.file.localeCompare(b.file));
                } catch (listErr) {
                    throw new Error(`Cannot access flows/ directory: ${listErr.message}`);
                }
            }
        }

        if (chunksMeta.length === 0) {
            throw new Error('No flow chunks found in flows/ directory.');
        }

        // Store state for on-demand chunk loading
        chunkedFlowState = {
            folderHandle,
            flowsDir,
            chunksMeta,
            manifest: result.manifest,
            chunkCache: new Map(),  // Cache for loaded chunks
            isV3Format: isV3Format
        };

        // Calculate totals from metadata
        let totalFlows = 0;
        let minTime = Infinity, maxTime = -Infinity;
        for (const chunk of chunksMeta) {
            totalFlows += chunk.count || 0;
            if (chunk.start && chunk.start < minTime) minTime = chunk.start;
            if (chunk.end && chunk.end > maxTime) maxTime = chunk.end;
        }
        const timeExtent = [minTime, maxTime];

        console.log(`[FolderIntegration] Loaded metadata for ${chunksMeta.length} chunks, ${totalFlows} total flows, v3=${isV3Format}`);

        hideProgress();

        // Dispatch flowDataLoaded event with chunk metadata (not all flows)
        // The overview chart will bin from this metadata
        // Actual flows are loaded on-demand when user clicks
        const actualFormat = isV3Format ? 'chunked_flows_by_ip_pair' : 'chunked_flows';
        const event = new CustomEvent('flowDataLoaded', {
            detail: {
                chunksMeta: chunksMeta,
                manifest: result.manifest,
                totalFlows: totalFlows,
                timeExtent: timeExtent,
                format: actualFormat,
                loadChunksForTimeRange: loadChunksForTimeRange  // On-demand loader
            }
        });
        document.dispatchEvent(event);

        console.log(`[FolderIntegration] Flow metadata loaded: ${chunksMeta.length} chunks, ${totalFlows} flows, time: ${timeExtent[0]} - ${timeExtent[1]}`);

    } catch (err) {
        hideProgress();
        console.error('[FolderIntegration] Error loading chunked flows:', err);
        alert(`Error loading chunked flows: ${err.message}`);
    }
}

/**
 * Load flows from chunks that overlap with a time range (on-demand)
 * @param {number} startTime - Start timestamp in microseconds
 * @param {number} endTime - End timestamp in microseconds
 * @param {Array<string>} selectedIPs - Optional array of selected IPs to filter by
 * @returns {Promise<Array>} Array of flow objects
 */
async function loadChunksForTimeRange(startTime, endTime, selectedIPs = null) {
    if (!chunkedFlowState) {
        console.warn('No chunked flow state available');
        return [];
    }

    const { flowsDir, chunksMeta, chunkCache } = chunkedFlowState;
    const selectedIPSet = selectedIPs ? new Set(selectedIPs) : null;

    // Find chunks that overlap with the time range
    const relevantChunks = chunksMeta.filter(chunk =>
        chunk.end >= startTime && chunk.start <= endTime
    );

    if (relevantChunks.length === 0) {
        return [];
    }

    const allFlows = [];

    for (const chunk of relevantChunks) {
        // Check cache first
        if (chunkCache.has(chunk.file)) {
            const cachedFlows = chunkCache.get(chunk.file);
            const filtered = cachedFlows.filter(f => {
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
            continue;
        }

        // Load chunk from disk
        try {
            // Handle nested paths for v3 format (e.g., by_pair/172-28-4-7__192-168-1-1/chunk_00000.json)
            let fileHandle;
            if (chunk.file.includes('/')) {
                const pathParts = chunk.file.split('/');
                let currentDir = flowsDir;
                for (let i = 0; i < pathParts.length - 1; i++) {
                    currentDir = await currentDir.getDirectoryHandle(pathParts[i]);
                }
                fileHandle = await currentDir.getFileHandle(pathParts[pathParts.length - 1]);
            } else {
                fileHandle = await flowsDir.getFileHandle(chunk.file);
            }
            const file = await fileHandle.getFile();
            const content = await file.text();
            const flows = JSON.parse(content).map(convertChunkedFlow);

            // Cache the chunk
            chunkCache.set(chunk.file, flows);

            // Filter to time range AND selected IPs
            const filtered = flows.filter(f => {
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
        } catch (err) {
            console.error(`Failed to load chunk ${chunk.file}:`, err);
        }
    }

    return allFlows;
}

/**
 * Convert a flow from tcp_data_loader_streaming.py format to visualization format
 */
function convertChunkedFlow(flow) {
    // The flow objects from tcp_data_loader_streaming.py already have camelCase names
    // and the structure we need, so we just ensure all required fields exist
    return {
        // Identity
        id: flow.id,
        key: flow.key,

        // Endpoints
        initiator: flow.initiator,
        responder: flow.responder,
        initiatorPort: flow.initiatorPort,
        responderPort: flow.responderPort,

        // Timing
        startTime: flow.startTime,
        endTime: flow.endTime,

        // State
        state: flow.state,
        closeType: flow.closeType,
        invalidReason: flow.invalidReason,

        // Flags
        establishmentComplete: flow.establishmentComplete || false,
        dataTransferStarted: flow.dataTransferStarted || false,
        closingStarted: flow.closingStarted || false,
        ongoing: flow.ongoing || false,

        // Stats
        totalPackets: flow.totalPackets || 0,
        totalBytes: flow.totalBytes || 0,

        // Phases (for packet counts in UI)
        phases: flow.phases || {
            establishment: [],
            dataTransfer: [],
            closing: []
        },

        // Full packets if available
        packets: flow.packets || []
    };
}

/**
 * Load flows for a specific time range (on-demand)
 * @param {number} startTime - Start timestamp in microseconds
 * @param {number} endTime - End timestamp in microseconds
 * @returns {Promise<Array>} Array of flow objects
 */
async function loadFlowsForTimeRange(startTime, endTime) {
    if (!flowResolutionState) {
        console.warn('[FlowLoader] No flow resolution state available');
        return [];
    }

    const { rawDir, rawIndex, flowCache } = flowResolutionState;

    // Find chunks that overlap with the time range
    const relevantChunks = rawIndex.chunks.filter(chunk =>
        chunk.end >= startTime && chunk.start <= endTime
    );

    if (relevantChunks.length === 0) {
        console.log(`[FlowLoader] No chunks found for time range`);
        return [];
    }

    console.log(`[FlowLoader] Loading ${relevantChunks.length} chunks for time range`);

    const allFlows = [];

    for (const chunk of relevantChunks) {
        // Check cache first
        if (flowCache.has(chunk.file)) {
            const cachedFlows = flowCache.get(chunk.file);
            const filtered = cachedFlows.filter(f =>
                f.startTime <= endTime && f.endTime >= startTime
            );
            allFlows.push(...filtered);
            continue;
        }

        // Load chunk
        try {
            const file = await rawDir.getFileHandle(chunk.file);
            const csvText = await (await file.getFile()).text();
            const flows = parseFlowCSV(csvText);

            // Cache the chunk
            flowCache.set(chunk.file, flows);

            // Filter to time range
            const filtered = flows.filter(f =>
                f.startTime <= endTime && f.endTime >= startTime
            );
            allFlows.push(...filtered);

            console.log(`[FlowLoader] Loaded ${chunk.file}: ${flows.length} flows, ${filtered.length} in range`);
        } catch (err) {
            console.error(`[FlowLoader] Failed to load ${chunk.file}:`, err);
        }
    }

    console.log(`[FlowLoader] Total flows for time range: ${allFlows.length}`);
    return allFlows;
}

/**
 * Get flow resolution state (for external access)
 */
function getFlowResolutionState() {
    return flowResolutionState;
}

/**
 * Get chunked flow state (for external access)
 */
function getChunkedFlowState() {
    return chunkedFlowState;
}

/**
 * Load a flow's full detail with embedded packets from flow folder
 * @param {Object} flowSummary - Flow summary object with id, startTime, endTime
 * @returns {Promise<Object>} Flow object with full packet data in phases
 */
async function loadFlowDetailWithPackets(flowSummary) {
    console.log('[FlowDetail] loadFlowDetailWithPackets called with:', flowSummary);
    console.log('[FlowDetail] chunkedFlowState:', chunkedFlowState ? 'exists' : 'null');

    if (!chunkedFlowState) {
        console.warn('[FlowDetail] No chunked flow state available - flow folder may not be loaded');
        return null;
    }

    const { flowsDir, chunksMeta, chunkCache } = chunkedFlowState;
    console.log('[FlowDetail] flowsDir:', flowsDir ? 'exists' : 'null');
    console.log('[FlowDetail] chunksMeta length:', chunksMeta ? chunksMeta.length : 0);

    const flowId = flowSummary.id;
    const flowStartTime = flowSummary.startTime;

    console.log(`[FlowDetail] Loading detail for flow ${flowId}, startTime: ${flowStartTime}`);

    // Find ALL chunks that could contain this flow based on time range AND IPs
    // Note: Chunks can have overlapping time ranges, so we need to search multiple chunks
    const { initiator, responder, initiatorPort, responderPort } = flowSummary;

    console.log(`[FlowDetail] Searching for chunk containing flow with startTime ${flowStartTime}`);
    console.log(`[FlowDetail] Connection: ${initiator}:${initiatorPort} ↔ ${responder}:${responderPort}`);
    console.log(`[FlowDetail] First few chunk time ranges:`, chunksMeta.slice(0, 5).map(c => ({file: c.file, start: c.start, end: c.end})));

    // Collect all candidate chunks (matching time range and IPs)
    const candidateChunks = [];
    for (const chunk of chunksMeta) {
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

    console.log(`[FlowDetail] Found ${candidateChunks.length} candidate chunks`);

    if (candidateChunks.length === 0) {
        console.error(`[FlowDetail] No chunks match flow ${flowId} (${initiator} ↔ ${responder} @ ${flowStartTime})`);
        return null;
    }

    // Search through all candidate chunks until we find the flow
    for (const chunk of candidateChunks) {
        console.log(`[FlowDetail] Searching chunk ${chunk.file}...`);
        const flows = await loadChunkFromCache(chunk.file, flowsDir, chunkCache);

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
            console.log(`[FlowDetail] ✅ Found flow ${flowId} in ${chunk.file} with ${countFlowPackets(flow)} packets`);
            return flow;
        }
        console.log(`[FlowDetail] Flow not in ${chunk.file}, continuing search...`);
    }

    console.error(`[FlowDetail] ❌ Flow ${flowId} not found in any of ${candidateChunks.length} candidate chunks`);
    return null;
}

/**
 * Load chunk from cache or disk
 * Note: Returns raw flows with full packet data in phases
 */
async function loadChunkFromCache(chunkFile, flowsDir, chunkCache) {
    // Check if chunk is already cached
    // Note: loadChunksForTimeRange may have cached converted flows - we need raw flows
    // Use a different cache key for raw flows
    const rawCacheKey = `raw:${chunkFile}`;

    if (chunkCache.has(rawCacheKey)) {
        console.log(`[FlowDetail] Using cached raw flows from ${chunkFile}`);
        return chunkCache.get(rawCacheKey);
    }

    try {
        console.log(`[FlowDetail] Loading chunk from disk: ${chunkFile}`);
        const fileHandle = await flowsDir.getFileHandle(chunkFile);
        const file = await fileHandle.getFile();
        const content = await file.text();
        const flows = JSON.parse(content);

        // Cache raw flows separately from converted flows
        chunkCache.set(rawCacheKey, flows);

        console.log(`[FlowDetail] Loaded ${flows.length} raw flows from ${chunkFile}`);
        if (flows.length > 0) {
            const sample = flows[0];
            console.log(`[FlowDetail] Sample flow structure:`, {
                id: sample.id,
                hasPhases: !!sample.phases,
                establishmentCount: sample.phases?.establishment?.length || 0,
                dataTransferCount: sample.phases?.dataTransfer?.length || 0,
                closingCount: sample.phases?.closing?.length || 0
            });
        }

        return flows;
    } catch (err) {
        console.error(`[FlowDetail] Failed to load ${chunkFile}:`, err);
        return [];
    }
}

/**
 * Count total packets in a flow's phases
 */
function countFlowPackets(flow) {
    if (!flow || !flow.phases) return 0;
    const est = flow.phases.establishment?.length || 0;
    const data = flow.phases.dataTransfer?.length || 0;
    const close = flow.phases.closing?.length || 0;
    return est + data + close;
}

/**
 * Extract all packets from a flow's phases into a flat array
 * @param {Object} flow - Flow object with phases containing packets
 * @returns {Array} Array of packet objects with phase info
 */
function extractPacketsFromFlow(flow) {
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
 * Load flows from multires_flows format (tcp_flow_detector output)
 */
async function loadFlowsFromMultiRes(folderHandle, onProgress) {
    const resDir = await folderHandle.getDirectoryHandle('resolutions');
    const rawDir = await resDir.getDirectoryHandle('raw');

    // Load index
    const indexFile = await rawDir.getFileHandle('index.json');
    const index = JSON.parse(await (await indexFile.getFile()).text());

    const allFlows = [];
    const totalChunks = index.chunks.length;

    // Load all raw chunks
    for (let i = 0; i < totalChunks; i++) {
        const chunk = index.chunks[i];
        const file = await rawDir.getFileHandle(chunk.file);
        const csvText = await (await file.getFile()).text();
        const flows = parseFlowCSV(csvText);
        allFlows.push(...flows);

        if (onProgress) {
            onProgress(((i + 1) / totalChunks) * 100, allFlows.length, index.total_count);
        }
    }

    console.log(`[FlowLoader] Loaded ${allFlows.length} flows from ${totalChunks} chunks`);
    return allFlows;
}

/**
 * Parse flow CSV and convert to visualization format
 */
function parseFlowCSV(csvText) {
    const lines = csvText.split('\n').filter(l => l.trim());
    if (lines.length < 2) return [];

    const headers = lines[0].split(',').map(h => h.trim());
    const flows = [];

    for (let i = 1; i < lines.length; i++) {
        const values = lines[i].split(',');
        const row = {};
        headers.forEach((h, j) => row[h] = values[j]?.trim() || '');
        flows.push(convertFlowRow(row));
    }

    return flows;
}

/**
 * Convert a raw flow CSV row to visualization format
 */
function convertFlowRow(row) {
    const validity = row.validity || '';

    return {
        // Identity
        id: row.flow_id,
        key: row.connection_key,

        // Endpoints (snake_case → camelCase)
        initiator: row.initiator_ip,
        responder: row.responder_ip,
        initiatorPort: parseInt(row.initiator_port) || 0,
        responderPort: parseInt(row.responder_port) || 0,

        // Timing
        startTime: parseInt(row.start_time) || 0,
        endTime: parseInt(row.end_time) || 0,

        // State mapping
        closeType: mapFlowCloseType(validity, row.close_type),
        state: mapFlowState(validity),
        invalidReason: mapFlowInvalidReason(row.invalid_reason, validity),
        validity: validity,

        // Derived
        establishmentComplete: validity.startsWith('valid'),

        // Stats
        totalPackets: parseInt(row.total_packets) || 0,
        totalBytes: parseInt(row.total_bytes) || 0,

        // Phase counts for UI
        phases: {
            establishment: Array(parseInt(row.establishment_packets) || 0).fill({}),
            dataTransfer: Array(parseInt(row.data_packets) || 0).fill({}),
            closing: Array(parseInt(row.closing_packets) || 0).fill({})
        }
    };
}

function mapFlowCloseType(validity, closeType) {
    if (closeType && closeType !== '') return closeType;
    if (validity === 'valid_complete') return 'graceful';
    if (validity === 'valid_reset') return 'abortive';
    if (validity === 'valid_ongoing') return 'open';
    if (validity.startsWith('invalid')) return 'invalid';
    return 'open';
}

function mapFlowState(validity) {
    const stateMap = {
        'valid_complete': 'closed',
        'valid_reset': 'reset',
        'valid_ongoing': 'established',
        'invalid_rst_early': 'invalid',
        'invalid_incomplete': 'invalid',
        'invalid_handshake': 'invalid'
    };
    return stateMap[validity] || 'unknown';
}

function mapFlowInvalidReason(reason, validity) {
    // Direct mapping for Python → JS naming
    const reasonMap = {
        'no_synack': 'incomplete_no_synack',
        'no_ack': 'incomplete_no_ack',
        'no_syn': 'incomplete_no_syn'
    };

    if (reason && reasonMap[reason]) return reasonMap[reason];
    if (reason) return reason;

    // Derive from validity if no explicit reason
    if (validity === 'invalid_rst_early') return 'rst_during_handshake';
    if (validity === 'invalid_handshake') return 'invalid_ack';

    return null;
}

/**
 * Parse seconds CSV for flow-based timeline overview
 */
function parseFlowSecondsCSV(csvText) {
    const lines = csvText.split('\n').filter(l => l.trim());
    if (lines.length < 2) return [];

    const headers = lines[0].split(',').map(h => h.trim());
    const bins = [];

    for (let i = 1; i < lines.length; i++) {
        const values = lines[i].split(',');
        const row = {};
        headers.forEach((h, j) => row[h] = parseInt(values[j]?.trim()) || 0);

        bins.push({
            timestamp: row.timestamp || row.bin_start,
            binStart: row.bin_start,
            binEnd: row.bin_end,
            binCenter: Math.floor((row.bin_start + row.bin_end) / 2),
            count: row.total_packets,
            activeFlows: row.active_flows,
            startedFlows: row.started_flows,
            endedFlows: row.ended_flows,
            validFlows: row.valid_flows,
            invalidFlows: row.invalid_flows,
            totalBytes: row.total_bytes,
            binned: true,
            preBinnedSize: 1_000_000,
            resolution: 'seconds'
        });
    }

    return bins;
}

/**
 * Extract unique IPs from aggregated bin data
 */
function extractUniqueIPsFromBins(bins) {
    const ips = new Set();
    for (const bin of bins) {
        if (bin.src_ip) ips.add(bin.src_ip);
        if (bin.dst_ip) ips.add(bin.dst_ip);
    }
    return Array.from(ips).sort();
}

/**
 * Format time range for display
 */
function formatTimeRange(extent) {
    if (!extent || extent.length < 2) return 'Unknown';
    const start = new Date(extent[0] / 1000);
    const end = new Date(extent[1] / 1000);
    const durationSec = (extent[1] - extent[0]) / 1_000_000;

    if (durationSec < 60) {
        return `${durationSec.toFixed(1)}s`;
    } else if (durationSec < 3600) {
        return `${(durationSec / 60).toFixed(1)} min`;
    } else if (durationSec < 86400) {
        return `${(durationSec / 3600).toFixed(1)} hours`;
    } else {
        return `${(durationSec / 86400).toFixed(1)} days`;
    }
}

/**
 * Trigger visualization with multi-resolution data
 */
function triggerMultiResVisualization(secondsData, uniqueIPs, manifest) {
    // Create synthetic packet-like objects from seconds bins for initial visualization
    const packets = secondsData.map(bin => ({
        timestamp: bin.binStart || bin.timestamp,
        src_ip: bin.src_ip,
        dst_ip: bin.dst_ip,
        flags: bin.flags || 0,
        length: bin.total_bytes || 0,
        count: bin.count || 1,
        binned: true,
        binStart: bin.binStart || bin.timestamp,
        binEnd: bin.binEnd || (bin.timestamp + 1_000_000),
        binCenter: bin.binCenter || bin.timestamp,
        flagType: bin.flag_type || bin.flagType || 'OTHER',
        preBinnedSize: 1_000_000,  // 1 second bins
        resolution: 'seconds'
    }));

    // Dispatch custom event with multi-resolution flag
    const event = new CustomEvent('folderDataLoaded', {
        detail: {
            packets: packets,
            flowsIndex: [],  // No flow data in pure packet view mode
            ipStats: {},
            flagStats: {},
            manifest: manifest || { format: 'multires_packets' },
            sourceType: 'folder',
            // Multi-resolution specific
            isAggregated: true,
            useMultiResolution: true,
            useCsvMultiRes: true,
            resolutionManager: csvResolutionManager,
            dataSource: null  // Not using DuckDB
        }
    });
    document.dispatchEvent(event);

    console.log('[FolderIntegration] Multi-resolution data event dispatched');
}

/**
 * Show progress indicator
 */
function showProgress(message, percent) {
    const progressDiv = document.getElementById('csvProgress');
    const progressLabel = document.getElementById('csvProgressLabel');
    const progressBar = document.getElementById('csvProgressBar');
    
    progressDiv.style.display = 'block';
    progressLabel.textContent = message;
    progressBar.style.width = `${Math.min(100, Math.max(0, percent))}%`;
}

/**
 * Hide progress indicator
 */
function hideProgress() {
    const progressDiv = document.getElementById('csvProgress');
    progressDiv.style.display = 'none';
}

/**
 * Trigger visualization from folder data
 * This function bridges folder data to the existing visualization
 */
function triggerVisualizationFromFolder(packets, flowsIndex, ipStats, flagStats, manifest) {
    console.log('Setting up visualization with folder data...');
    
    // Create synthetic event-like object to mimic file upload
    const syntheticData = {
        packets: packets,
        flowsIndex: flowsIndex,
        ipStats: ipStats,
        flagStats: flagStats,
        manifest: manifest,
        sourceType: 'folder',
        isAggregated: true  // Data is pre-binned at seconds level
    };
    
    // Dispatch custom event that the visualization can listen to
    const event = new CustomEvent('folderDataLoaded', { 
        detail: syntheticData 
    });
    document.dispatchEvent(event);
    
    console.log('Folder data loaded event dispatched');
}

/**
 * Handle IP selection change (called by visualization)
 * Filters flows by selected IPs
 */
export function onIPSelectionChange(newSelectedIPs) {
    selectedIPs = newSelectedIPs;
    
    if (currentMode !== 'folder' || !currentFlowsIndex.length) {
        return null;
    }
    
    // Filter flows by selected IPs
    const filteredFlows = folderLoader.filterFlowsByIPs(selectedIPs);
    console.log(`Filtered ${filteredFlows.length} flows for selected IPs`);
    
    return filteredFlows;
}

/**
 * Handle time range click on bar chart
 * Shows flow list modal for flows in that time range
 */
export async function onTimeRangeClick(startTime, endTime, selectedIPs) {
    if (currentMode !== 'folder' || !currentFlowsIndex.length) {
        return;
    }
    
    try {
        console.log(`Time range clicked: ${startTime} - ${endTime}`);
        
        // Filter flows by time range AND selected IPs
        let flows = folderLoader.filterFlowsByTimeRange(startTime, endTime);
        
        if (selectedIPs && selectedIPs.length > 0) {
            const ipSet = new Set(selectedIPs);
            flows = flows.filter(flow => 
                ipSet.has(flow.initiator) && ipSet.has(flow.responder)
            );
        }
        
        console.log(`Found ${flows.length} flows in time range`);
        
        if (flows.length === 0) {
            alert('No flows found in the selected time range');
            return;
        }
        
        // Show flow list modal
        showFlowListModal(flows, startTime, endTime);
        
    } catch (err) {
        console.error('Error handling time range click:', err);
        alert(`Error: ${err.message}`);
    }
}

/**
 * Show flow list modal for a time range
 */
function showFlowListModal(flows, startTime, endTime) {
    // Get or create modal elements
    let modal = document.getElementById('timeRangeFlowModal');
    if (!modal) {
        createTimeRangeFlowModal();
        modal = document.getElementById('timeRangeFlowModal');
    }
    
    const modalOverlay = document.getElementById('timeRangeFlowModalOverlay');
    const modalTitle = document.getElementById('timeRangeFlowModalTitle');
    const modalList = document.getElementById('timeRangeFlowModalList');
    const modalCount = document.getElementById('timeRangeFlowModalCount');
    
    // Update title with time range
    const startStr = new Date(startTime / 1000).toLocaleString();
    const endStr = new Date(endTime / 1000).toLocaleString();
    modalTitle.textContent = `Flows in Time Range`;
    modalCount.textContent = `${flows.length} flow(s) • ${startStr} - ${endStr}`;
    
    // Populate flow list
    modalList.innerHTML = '';
    flows.forEach(flow => {
        const flowItem = createFlowListItem(flow);
        modalList.appendChild(flowItem);
    });
    
    // Show modal
    modalOverlay.style.display = 'flex';
    
    // Setup search
    const searchInput = document.getElementById('timeRangeFlowModalSearch');
    searchInput.value = '';
    searchInput.oninput = () => {
        const term = searchInput.value.toLowerCase();
        const items = modalList.querySelectorAll('.flow-item');
        items.forEach(item => {
            const text = item.textContent.toLowerCase();
            item.style.display = text.includes(term) ? '' : 'none';
        });
    };
}

/**
 * Create flow list item element
 */
function createFlowListItem(flow) {
    const div = document.createElement('div');
    div.className = 'flow-item';
    div.style.cssText = 'padding: 10px; margin-bottom: 8px; border: 1px solid #e9ecef; border-radius: 4px; background: #f8f9fa; cursor: pointer;';
    
    const startTime = new Date(flow.startTime / 1000).toLocaleTimeString();
    const duration = ((flow.endTime - flow.startTime) / 1000000).toFixed(2);
    
    div.innerHTML = `
        <div style="font-weight: bold; margin-bottom: 4px; color: #2c3e50;">
            ${flow.initiator}:${flow.initiatorPort} ↔ ${flow.responder}:${flow.responderPort}
        </div>
        <div style="font-size: 11px; color: #666; display: flex; gap: 15px; flex-wrap: wrap;">
            <span>⏱ ${startTime}</span>
            <span>⏳ ${duration}s</span>
            <span>📦 ${flow.totalPackets} pkts</span>
            <span>📊 ${formatBytes(flow.totalBytes)}</span>
            <span class="flow-status ${flow.state}">${flow.state}</span>
        </div>
    `;
    
    // Click to load and show flow details
    div.onclick = async () => {
        await loadAndShowFlowDetails(flow);
    };
    
    return div;
}

/**
 * Format bytes for display
 */
function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

/**
 * Load and show detailed flow information
 */
async function loadAndShowFlowDetails(flowSummary) {
    try {
        console.log(`Loading flow details: ${flowSummary.id}`);
        
        // Show loading indicator
        const loadingDiv = document.createElement('div');
        loadingDiv.style.cssText = 'position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); padding: 20px; background: white; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); z-index: 10000;';
        loadingDiv.textContent = 'Loading flow details...';
        document.body.appendChild(loadingDiv);
        
        // Load full flow data
        const flow = await folderLoader.loadFlow(flowSummary.id);
        
        document.body.removeChild(loadingDiv);
        
        // Show flow details in a new modal or panel
        showFlowDetailsModal(flow);
        
    } catch (err) {
        console.error('Error loading flow details:', err);
        alert(`Error loading flow: ${err.message}`);
    }
}

/**
 * Show detailed flow modal
 */
function showFlowDetailsModal(flow) {
    // Create or get flow details modal
    let modal = document.getElementById('flowDetailsModal');
    if (!modal) {
        createFlowDetailsModal();
        modal = document.getElementById('flowDetailsModal');
    }
    
    const modalOverlay = document.getElementById('flowDetailsModalOverlay');
    const modalContent = document.getElementById('flowDetailsModalContent');
    
    // Build detailed view
    const startTime = new Date(flow.startTime / 1000).toLocaleString();
    const endTime = new Date(flow.endTime / 1000).toLocaleString();
    const duration = ((flow.endTime - flow.startTime) / 1000000).toFixed(3);
    
    modalContent.innerHTML = `
        <h3 style="margin-top: 0; color: #2c3e50;">Flow Details</h3>
        
        <div style="margin-bottom: 20px;">
            <h4>Connection</h4>
            <div style="font-family: monospace; background: #f8f9fa; padding: 10px; border-radius: 4px;">
                ${flow.initiator}:${flow.initiatorPort} ↔ ${flow.responder}:${flow.responderPort}
            </div>
        </div>
        
        <div style="margin-bottom: 20px;">
            <h4>Summary</h4>
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 4px;"><strong>State:</strong></td><td>${flow.state}</td></tr>
                <tr><td style="padding: 4px;"><strong>Close Type:</strong></td><td>${flow.closeType || 'N/A'}</td></tr>
                <tr><td style="padding: 4px;"><strong>Start Time:</strong></td><td>${startTime}</td></tr>
                <tr><td style="padding: 4px;"><strong>End Time:</strong></td><td>${endTime}</td></tr>
                <tr><td style="padding: 4px;"><strong>Duration:</strong></td><td>${duration} seconds</td></tr>
                <tr><td style="padding: 4px;"><strong>Total Packets:</strong></td><td>${flow.totalPackets}</td></tr>
                <tr><td style="padding: 4px;"><strong>Total Bytes:</strong></td><td>${formatBytes(flow.totalBytes)}</td></tr>
            </table>
        </div>
        
        <div style="margin-bottom: 20px;">
            <h4>Phases</h4>
            <div style="display: flex; gap: 20px;">
                <div>
                    <strong>Establishment:</strong> ${flow.phases.establishment.length} packets
                </div>
                <div>
                    <strong>Data Transfer:</strong> ${flow.phases.dataTransfer.length} packets
                </div>
                <div>
                    <strong>Closing:</strong> ${flow.phases.closing.length} packets
                </div>
            </div>
        </div>
        
        <div style="margin-bottom: 20px;">
            <h4>Packets (${flow.packets.length})</h4>
            <div style="max-height: 300px; overflow-y: auto; border: 1px solid #dee2e6; border-radius: 4px;">
                <table style="width: 100%; font-size: 11px; border-collapse: collapse;">
                    <thead style="background: #f8f9fa; position: sticky; top: 0;">
                        <tr>
                            <th style="padding: 6px; text-align: left;">Time</th>
                            <th style="padding: 6px; text-align: left;">Source</th>
                            <th style="padding: 6px; text-align: left;">Dest</th>
                            <th style="padding: 6px; text-align: left;">Flags</th>
                            <th style="padding: 6px; text-align: right;">Length</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${flow.packets.map(pkt => `
                            <tr style="border-bottom: 1px solid #e9ecef;">
                                <td style="padding: 6px;">${new Date(pkt.timestamp / 1000).toLocaleTimeString()}</td>
                                <td style="padding: 6px;">${pkt.src_ip}:${pkt.src_port}</td>
                                <td style="padding: 6px;">${pkt.dst_ip}:${pkt.dst_port}</td>
                                <td style="padding: 6px;">${pkt.flag_type}</td>
                                <td style="padding: 6px; text-align: right;">${pkt.length}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
    
    // Show modal
    modalOverlay.style.display = 'flex';
}

/**
 * Create time range flow modal
 */
function createTimeRangeFlowModal() {
    const overlay = document.createElement('div');
    overlay.id = 'timeRangeFlowModalOverlay';
    overlay.className = 'modal-overlay';
    overlay.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: none; align-items: center; justify-content: center; z-index: 2000;';
    
    const modal = document.createElement('div');
    modal.id = 'timeRangeFlowModal';
    modal.className = 'modal';
    modal.style.cssText = 'background: white; width: min(600px, 90vw); max-height: 80vh; border-radius: 8px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); display: flex; flex-direction: column; overflow: hidden;';
    
    modal.innerHTML = `
        <div class="modal-header" style="padding: 15px; border-bottom: 1px solid #e9ecef;">
            <h3 id="timeRangeFlowModalTitle" style="margin: 0; font-size: 16px; color: #2c3e50;">Flows</h3>
            <div id="timeRangeFlowModalCount" style="margin-top: 4px; color: #6c757d; font-size: 12px;"></div>
        </div>
        <div class="modal-body" style="padding: 15px; overflow: auto; flex: 1;">
            <input type="text" id="timeRangeFlowModalSearch" placeholder="Search flows..." style="width: 100%; padding: 8px; margin-bottom: 10px; border: 1px solid #ced4da; border-radius: 4px;">
            <div id="timeRangeFlowModalList"></div>
        </div>
        <div class="modal-actions" style="padding: 10px 15px; border-top: 1px solid #e9ecef; display: flex; justify-content: flex-end;">
            <button id="timeRangeFlowModalClose" style="padding: 6px 12px; border: 1px solid #ced4da; background: white; border-radius: 4px; cursor: pointer;">Close</button>
        </div>
    `;
    
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    
    // Close button
    document.getElementById('timeRangeFlowModalClose').onclick = () => {
        overlay.style.display = 'none';
    };
    
    // Click outside to close
    overlay.onclick = (e) => {
        if (e.target === overlay) {
            overlay.style.display = 'none';
        }
    };
}

/**
 * Create flow details modal
 */
function createFlowDetailsModal() {
    const overlay = document.createElement('div');
    overlay.id = 'flowDetailsModalOverlay';
    overlay.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.5); display: none; align-items: center; justify-content: center; z-index: 3000;';
    
    const modal = document.createElement('div');
    modal.id = 'flowDetailsModal';
    modal.style.cssText = 'background: white; width: min(800px, 90vw); max-height: 90vh; border-radius: 8px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); display: flex; flex-direction: column; overflow: hidden;';
    
    modal.innerHTML = `
        <div id="flowDetailsModalContent" style="padding: 20px; overflow: auto; flex: 1;"></div>
        <div style="padding: 10px 20px; border-top: 1px solid #e9ecef; display: flex; justify-content: flex-end;">
            <button id="flowDetailsModalClose" style="padding: 8px 16px; border: 1px solid #ced4da; background: white; border-radius: 4px; cursor: pointer;">Close</button>
        </div>
    `;
    
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
    
    // Close button
    document.getElementById('flowDetailsModalClose').onclick = () => {
        overlay.style.display = 'none';
    };
    
    // Click outside to close
    overlay.onclick = (e) => {
        if (e.target === overlay) {
            overlay.style.display = 'none';
        }
    };
}

// Export for use by visualization
export {
    currentMode,
    folderLoader,
    useCsvMultiRes,
    csvResolutionManager,
    loadFlowsForTimeRange,
    getFlowResolutionState,
    getChunkedFlowState,
    loadFlowDetailWithPackets,
    extractPacketsFromFlow
};
