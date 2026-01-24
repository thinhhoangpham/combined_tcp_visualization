// src/data/packet-filter.js
// Packet filtering utilities for IP-based filtering

import { DEBUG } from '../config/constants.js';
import { LOG } from '../utils/formatters.js';

/**
 * Get selected IPs from the DOM checkbox list.
 * @returns {string[]} Array of selected IP addresses
 */
export function getSelectedIPsFromDOM() {
    return Array.from(
        document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')
    ).map(cb => cb.value);
}

/**
 * Build a set of normalized IP pair keys for all combinations of selected IPs.
 * Used for efficient lookup when filtering flows.
 * @param {string[]} selectedIPs - Array of selected IP addresses
 * @returns {Set<string>} Set of normalized pair keys like "ip1<->ip2" (sorted)
 */
export function buildIPPairKeys(selectedIPs) {
    const pairs = new Set();
    for (let i = 0; i < selectedIPs.length; i++) {
        for (let j = i + 1; j < selectedIPs.length; j++) {
            const ip1 = selectedIPs[i];
            const ip2 = selectedIPs[j];
            const pairKey = ip1 < ip2 ? `${ip1}<->${ip2}` : `${ip2}<->${ip1}`;
            pairs.add(pairKey);
        }
    }
    return pairs;
}

/**
 * Filter packets by selected IPs with caching.
 * Only returns packets where BOTH src_ip AND dst_ip are in the selected set.
 * @param {Object} options
 * @param {Array} options.packets - All packets to filter
 * @param {string[]} options.selectedIPs - Selected IP addresses
 * @param {Map} options.filterCache - Cache for filtered results
 * @returns {Object} { filtered, cacheKey, fromCache }
 */
export function filterPacketsByIPs(options) {
    const { packets, selectedIPs, filterCache } = options;

    if (!packets || packets.length === 0) {
        return { filtered: [], cacheKey: '', fromCache: false };
    }

    const selectedIPSet = new Set(selectedIPs);
    const cacheKey = selectedIPs.slice().sort().join('|');

    // Handle case with fewer than 2 IPs (can't show links)
    if (selectedIPs.length < 2) {
        if (filterCache.has(cacheKey)) {
            return {
                filtered: filterCache.get(cacheKey),
                cacheKey,
                fromCache: true
            };
        }
        filterCache.set(cacheKey, []);
        return { filtered: [], cacheKey, fromCache: false };
    }

    // Check cache
    if (filterCache.has(cacheKey)) {
        const cached = filterCache.get(cacheKey);
        if (DEBUG) LOG('Using cached filtered packets for key', cacheKey, 'len', cached.length);
        return { filtered: cached, cacheKey, fromCache: true };
    }

    // Filter packets where both ends are in selected IPs
    const filtered = packets.filter(packet =>
        selectedIPSet.has(packet.src_ip) && selectedIPSet.has(packet.dst_ip)
    );

    filterCache.set(cacheKey, filtered);
    if (DEBUG) LOG('Cached filtered packets for key', cacheKey, 'len', filtered.length);

    return { filtered, cacheKey, fromCache: false };
}

/**
 * Create a Set from selected IPs for O(1) lookup.
 * @param {string[]} selectedIPs - Array of selected IP addresses
 * @returns {Set<string>} Set of selected IPs
 */
export function createSelectedIPSet(selectedIPs) {
    return new Set(selectedIPs);
}
