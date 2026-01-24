// src/rendering/circles.js
// Circle rendering for packet visualization

import { getFlagType } from '../tcp/flags.js';

/**
 * Render circles for binned items into a layer.
 * @param {Object} layer - D3 selection (g element)
 * @param {Array} binned - Binned packet data
 * @param {Object} options - Rendering options
 */
export function renderCircles(layer, binned, options) {
    const {
        xScale,
        rScale,
        flagColors,
        RADIUS_MIN,
        mainGroup,
        arcPathGenerator,
        findIPPosition,
        pairs,
        ipPositions,
        createTooltipHTML,
        FLAG_CURVATURE,
        d3
    } = options;

    if (!layer) return;

    // Clear bar segments in this layer
    try { layer.selectAll('.bin-bar-segment').remove(); } catch {}
    try { layer.selectAll('.bin-stack').remove(); } catch {}

    const tooltip = d3.select('#tooltip');

    // Key function: for pre-binned data, use all identifying fields to prevent merging
    // Use flagType string directly (from CSV) instead of getFlagType() which may return "NONE"
    const getDataKey = d => {
        if (d.binned) {
            const flagStr = d.flagType || d.flag_type || getFlagType(d);
            return `bin_${d.timestamp}_${d.src_ip}_${d.dst_ip}_${flagStr}`;
        }
        return `${d.src_ip}-${d.dst_ip}-${d.timestamp}-${d.src_port || 0}-${d.dst_port || 0}`;
    };

    // Helper to get flag color - prefer flagType string from pre-binned data
    const getFlagColor = d => {
        const flagStr = d.flagType || d.flag_type || getFlagType(d);
        return flagColors[flagStr] || flagColors.OTHER;
    };

    layer.selectAll('.direction-dot')
        .data(binned, getDataKey)
        .join(
            enter => enter.append('circle')
                .attr('class', d => `direction-dot ${d.binned && d.count > 1 ? 'binned' : ''}`)
                .attr('r', d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN)
                .attr('data-orig-r', d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN)
                .attr('fill', getFlagColor)
                .attr('cx', d => xScale(Math.floor(d.binned && Number.isFinite(d.binCenter) ? d.binCenter : d.timestamp)))
                .attr('cy', d => d.binned ? d.yPos : findIPPosition(d.src_ip, d.src_ip, d.dst_ip, pairs, ipPositions))
                .style('cursor', 'pointer')
                .on('mouseover', (event, d) => {
                    const dot = d3.select(event.currentTarget);
                    dot.classed('highlighted', true).style('stroke', '#000').style('stroke-width', '2px');
                    const baseR = +dot.attr('data-orig-r') || +dot.attr('r') || RADIUS_MIN;
                    dot.attr('r', baseR);
                    const packet = d.originalPackets ? d.originalPackets[0] : d;
                    const arcPath = arcPathGenerator(packet, { xScale, ipPositions, pairs, findIPPosition, flagCurvature: FLAG_CURVATURE });
                    if (arcPath) {
                        mainGroup.append('path').attr('class', 'hover-arc').attr('d', arcPath)
                            .style('stroke', getFlagColor(d))
                            .style('stroke-width', '2px')
                            .style('stroke-opacity', 0.8).style('fill', 'none').style('pointer-events', 'none');
                    }
                    tooltip.style('display', 'block').html(createTooltipHTML(d));
                })
                .on('mousemove', e => { tooltip.style('left', `${e.pageX + 40}px`).style('top', `${e.pageY - 40}px`); })
                .on('mouseout', e => {
                    const dot = d3.select(e.currentTarget);
                    dot.classed('highlighted', false).style('stroke', null).style('stroke-width', null);
                    const baseR = +dot.attr('data-orig-r') || RADIUS_MIN; dot.attr('r', baseR);
                    mainGroup.selectAll('.hover-arc').remove(); tooltip.style('display', 'none');
                }),
            update => update
                .attr('class', d => `direction-dot ${d.binned && d.count > 1 ? 'binned' : ''}`)
                .attr('r', d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN)
                .attr('data-orig-r', d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN)
                .attr('fill', getFlagColor)
                .attr('cx', d => xScale(Math.floor(d.binned && Number.isFinite(d.binCenter) ? d.binCenter : d.timestamp)))
                .attr('cy', d => d.binned ? d.yPos : findIPPosition(d.src_ip, d.src_ip, d.dst_ip, pairs, ipPositions))
                .style('cursor', 'pointer')
        );
}
