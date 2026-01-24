// src/layout/ipPositioning.js
// IP ordering and positioning logic for TimeArcs visualization

import { ROW_GAP, TOP_PAD } from '../config/constants.js';

/**
 * Count packets per IP address.
 * @param {Array} packets - Array of packet objects with src_ip and dst_ip
 * @returns {Map<string, number>} Map of IP -> packet count
 */
export function computeIPCounts(packets) {
    const ipCounts = new Map();
    packets.forEach(p => {
        if (p.src_ip) ipCounts.set(p.src_ip, (ipCounts.get(p.src_ip) || 0) + 1);
        if (p.dst_ip) ipCounts.set(p.dst_ip, (ipCounts.get(p.dst_ip) || 0) + 1);
    });
    return ipCounts;
}

/**
 * Compute IP ordering and vertical positions for TimeArcs visualization.
 *
 * @param {Array} packets - Array of packet objects with src_ip and dst_ip
 * @param {Object} options - Configuration options
 * @param {Object} options.state - Global state object with layout and timearcs properties
 * @param {number} [options.rowGap=ROW_GAP] - Vertical gap between IP rows
 * @param {number} [options.topPad=TOP_PAD] - Top padding for first row
 * @param {Array<string>} [options.timearcsOrder] - Optional TimeArcs IP order to use
 * @param {number} [options.dotRadius=40] - Dot radius for height calculation
 * @returns {Object} { ipOrder, ipPositions, yDomain, height, ipCounts }
 */
export function computeIPPositioning(packets, options = {}) {
    const {
        state,
        rowGap = ROW_GAP,
        topPad = TOP_PAD,
        timearcsOrder = null,
        dotRadius = 40
    } = options;

    // Count packets per IP
    const ipCounts = computeIPCounts(packets);
    const ipList = Array.from(new Set(Array.from(ipCounts.keys())));

    // Initialize result containers
    let ipOrder = [];
    const ipPositions = new Map();

    // Determine IP order based on available information
    const effectiveTimearcsOrder = timearcsOrder || (state?.timearcs?.ipOrder);

    if (effectiveTimearcsOrder && effectiveTimearcsOrder.length > 0) {
        // Use TimeArcs vertical order - filter to only IPs present in data
        const ipSet = new Set(ipList);
        ipOrder = effectiveTimearcsOrder.filter(ip => ipSet.has(ip));

        // Add any IPs in data but not in TimeArcs order at the end
        ipList.forEach(ip => {
            if (!effectiveTimearcsOrder.includes(ip)) {
                ipOrder.push(ip);
            }
        });

        // Assign vertical positions based on order
        ipOrder.forEach((ip, idx) => {
            ipPositions.set(ip, topPad + idx * rowGap);
        });
    } else if (!state?.layout?.ipOrder?.length ||
               !state?.layout?.ipPositions?.size ||
               state?.layout?.ipOrder?.length !== ipList.length) {
        // No TimeArcs order and force layout hasn't run - use simple sort by count
        const sortedIPs = ipList.slice().sort((a, b) => {
            const ca = ipCounts.get(a) || 0;
            const cb = ipCounts.get(b) || 0;
            if (cb !== ca) return cb - ca;
            return a.localeCompare(b);
        });

        // Initialize positions and order
        ipOrder = sortedIPs;
        sortedIPs.forEach((ip, idx) => {
            ipPositions.set(ip, topPad + idx * rowGap);
        });
    } else {
        // Use existing force layout computed positions
        ipOrder = state.layout.ipOrder.slice();
        state.layout.ipPositions.forEach((pos, ip) => {
            ipPositions.set(ip, pos);
        });
    }

    // Compute yDomain from order
    const yDomain = ipOrder.length > 0 ? ipOrder : ipList;
    const yRange = yDomain.map(ip => ipPositions.get(ip));
    const [minY, maxY] = yRange.length > 0
        ? [Math.min(...yRange), Math.max(...yRange)]
        : [0, 0];

    // Compute height
    const height = Math.max(500, (maxY ?? 0) + rowGap + dotRadius + topPad);

    return {
        ipOrder,
        ipPositions,
        yDomain,
        yRange,
        minY,
        maxY,
        height,
        ipCounts
    };
}

/**
 * Update state with computed IP positioning.
 * @param {Object} state - Global state object to update
 * @param {Object} positioning - Result from computeIPPositioning
 */
export function applyIPPositioningToState(state, positioning) {
    const { ipOrder, ipPositions } = positioning;

    state.layout.ipOrder = ipOrder;
    state.layout.ipPositions.clear();
    ipPositions.forEach((pos, ip) => {
        state.layout.ipPositions.set(ip, pos);
    });
}
