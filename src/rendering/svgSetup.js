// src/rendering/svgSetup.js
// SVG container and layer creation for TimeArcs visualization

/**
 * Create the main SVG structure with layers for rendering.
 *
 * @param {Object} options - Configuration options
 * @param {Object} options.d3 - D3 library reference
 * @param {string} options.containerId - Container element ID (default: '#chart')
 * @param {number} options.width - Chart width
 * @param {number} options.height - Chart height
 * @param {Object} options.margin - { top, right, bottom, left }
 * @param {number} [options.dotRadius=40] - Dot radius for clip path sizing
 * @returns {Object} { svgContainer, svg, mainGroup, fullDomainLayer, dynamicLayer }
 */
export function createSVGStructure(options) {
    const {
        d3,
        containerId = '#chart',
        width,
        height,
        margin,
        dotRadius = 40
    } = options;

    // Create outer SVG container
    const svgContainer = d3.select(containerId).append('svg')
        .attr('width', width + margin.left + margin.right)
        .attr('height', height + margin.top + margin.bottom);

    // Create main group with margin transform
    const svg = svgContainer.append('g')
        .attr('transform', `translate(${margin.left},${margin.top})`);

    // Create clip path for content bounds
    svg.append('defs').append('clipPath')
        .attr('id', 'clip')
        .append('rect')
        .attr('x', 0)
        .attr('y', -dotRadius)
        .attr('width', width + dotRadius)
        .attr('height', height + (2 * dotRadius));

    // Create clipped main group for marks
    const mainGroup = svg.append('g')
        .attr('clip-path', 'url(#clip)');

    // Create two layers for rendering optimization:
    // - fullDomainLayer: Pre-rendered full domain view (cached)
    // - dynamicLayer: Active rendering during zoom/pan
    const fullDomainLayer = mainGroup.append('g')
        .attr('class', 'dots-full-domain');
    const dynamicLayer = mainGroup.append('g')
        .attr('class', 'dots-dynamic');

    return {
        svgContainer,
        svg,
        mainGroup,
        fullDomainLayer,
        dynamicLayer
    };
}

/**
 * Create the bottom overlay with axis and duration label.
 *
 * @param {Object} options - Configuration options
 * @param {Object} options.d3 - D3 library reference
 * @param {string} options.overlaySelector - Selector for overlay SVG (default: '#chart-bottom-overlay-svg')
 * @param {number} options.width - Chart width
 * @param {number} options.chartMarginLeft - Left margin
 * @param {number} options.chartMarginRight - Right margin
 * @param {number} options.overlayHeight - Overlay height
 * @param {Function} options.xScale - X scale for axis
 * @param {Function} options.tickFormatter - Tick formatter function
 * @returns {Object} { bottomOverlaySvg, bottomOverlayRoot, bottomOverlayAxisGroup, bottomOverlayDurationLabel, bottomOverlayWidth }
 */
export function createBottomOverlay(options) {
    const {
        d3,
        overlaySelector = '#chart-bottom-overlay-svg',
        width,
        chartMarginLeft,
        chartMarginRight,
        overlayHeight,
        xScale,
        tickFormatter
    } = options;

    const bottomOverlayWidth = Math.max(0, width + chartMarginLeft + chartMarginRight);
    const bottomOverlaySvg = d3.select(overlaySelector);
    bottomOverlaySvg.attr('width', bottomOverlayWidth).attr('height', overlayHeight);

    // Get or create root group
    let bottomOverlayRoot = bottomOverlaySvg.select('g.overlay-root');
    if (bottomOverlayRoot.empty()) {
        bottomOverlayRoot = bottomOverlaySvg.append('g').attr('class', 'overlay-root');
    }
    bottomOverlayRoot.attr('transform', `translate(${chartMarginLeft},0)`);

    // Position axis near bottom
    const axisY = Math.max(20, overlayHeight - 20);

    // Remove existing axis and create new one
    bottomOverlaySvg.select('.main-bottom-axis').remove();
    const bottomOverlayAxisGroup = bottomOverlayRoot.append('g')
        .attr('class', 'x-axis axis main-bottom-axis')
        .attr('transform', `translate(0,${axisY})`)
        .call(d3.axisBottom(xScale).tickFormat(tickFormatter));

    // Remove existing label and create new one
    bottomOverlaySvg.select('.overlay-duration-label').remove();
    const bottomOverlayDurationLabel = bottomOverlayRoot.append('text')
        .attr('class', 'overlay-duration-label')
        .attr('x', width / 2)
        .attr('y', axisY - 12)
        .attr('text-anchor', 'middle')
        .style('font-size', '36px')
        .style('font-weight', '600')
        .style('fill', '#000')
        .style('opacity', 0.12)
        .text('');

    return {
        bottomOverlaySvg,
        bottomOverlayRoot,
        bottomOverlayAxisGroup,
        bottomOverlayDurationLabel,
        bottomOverlayWidth,
        axisY
    };
}

/**
 * Render IP row labels on the left gutter.
 *
 * @param {Object} options - Configuration options
 * @param {Object} options.d3 - D3 library reference
 * @param {Object} options.svg - D3 selection of main SVG group
 * @param {Array<string>} options.yDomain - Ordered list of IPs
 * @param {Map<string, number>} options.ipPositions - Map of IP -> y position
 * @param {Function} options.onHighlight - Highlight callback (ip) => void
 * @param {Function} options.onClearHighlight - Clear highlight callback () => void
 * @returns {Object} D3 selection of node groups
 */
export function renderIPRowLabels(options) {
    const {
        d3,
        svg,
        yDomain,
        ipPositions,
        onHighlight,
        onClearHighlight
    } = options;

    const nodes = svg.selectAll('.node')
        .data(yDomain)
        .enter()
        .append('g')
        .attr('class', 'node')
        .attr('transform', d => `translate(0,${ipPositions.get(d)})`);

    nodes.append('text')
        .attr('class', 'node-label')
        .attr('x', -10)
        .attr('dy', '.35em')
        .attr('text-anchor', 'end')
        .text(d => d)
        .on('mouseover', (e, d) => {
            if (onHighlight) {
                try { onHighlight({ ip: d }); } catch (_) { /* ignore */ }
            }
        })
        .on('mouseout', () => {
            if (onClearHighlight) {
                try { onClearHighlight(); } catch (_) { /* ignore */ }
            }
        });

    return nodes;
}

/**
 * Resize the bottom overlay to match chart width.
 *
 * @param {Object} options - Configuration options
 * @param {Object} options.d3 - D3 library reference
 * @param {string} options.overlaySelector - Selector for overlay SVG
 * @param {number} options.width - Chart width
 * @param {number} options.chartMarginLeft - Left margin
 * @param {number} options.chartMarginRight - Right margin
 * @param {number} options.overlayHeight - Overlay height
 * @param {Object} options.bottomOverlayRoot - Root group selection
 * @param {Object} options.bottomOverlayAxisGroup - Axis group selection
 * @param {Function} options.xScale - Current x scale
 * @param {Function} options.tickFormatter - Tick formatter
 */
export function resizeBottomOverlay(options) {
    const {
        d3,
        overlaySelector = '#chart-bottom-overlay-svg',
        width,
        chartMarginLeft,
        chartMarginRight,
        overlayHeight,
        bottomOverlayRoot,
        bottomOverlayAxisGroup,
        xScale,
        tickFormatter
    } = options;

    const bottomOverlayWidth = Math.max(0, width + chartMarginLeft + chartMarginRight);

    d3.select(overlaySelector)
        .attr('width', bottomOverlayWidth)
        .attr('height', overlayHeight);

    if (bottomOverlayRoot) {
        bottomOverlayRoot.attr('transform', `translate(${chartMarginLeft},0)`);
    }

    if (bottomOverlayAxisGroup && xScale) {
        bottomOverlayAxisGroup.call(d3.axisBottom(xScale).tickFormat(tickFormatter));
    }
}
