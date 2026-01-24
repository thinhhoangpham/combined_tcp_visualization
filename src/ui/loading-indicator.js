// src/ui/loading-indicator.js
// Loading overlay and progress indicators for UI feedback

/**
 * Show a centered loading overlay with a message.
 * @param {Object} d3 - D3 library reference
 * @param {string} message - Message to display
 * @returns {Object} D3 selection for the loading div (call .remove() to hide)
 */
export function showLoadingOverlay(d3, message = 'Updating interface...') {
    return d3.select('body').append('div')
        .style('position', 'fixed')
        .style('top', '50%')
        .style('left', '50%')
        .style('transform', 'translate(-50%, -50%)')
        .style('background', 'rgba(0,0,0,0.8)')
        .style('color', 'white')
        .style('padding', '20px')
        .style('border-radius', '5px')
        .style('z-index', '9999')
        .text(message);
}

/**
 * Hide/remove a loading overlay.
 * @param {Object} loadingDiv - D3 selection returned by showLoadingOverlay
 */
export function hideLoadingOverlay(loadingDiv) {
    if (loadingDiv) {
        loadingDiv.remove();
    }
}

/**
 * Create a progress indicator in a container element.
 * @param {HTMLElement} container - Container element to insert into
 * @param {string} id - Unique ID for the indicator
 * @param {Object} options - { initialText, totalChunks }
 * @returns {HTMLElement|null} The created indicator element
 */
export function createProgressIndicator(container, id, options = {}) {
    const { initialText = 'Loading...', totalChunks = 0 } = options;

    if (!container) {
        console.warn('[LOADING] Could not find container for progress indicator');
        return null;
    }

    const loadingDiv = document.createElement('div');
    loadingDiv.id = id;
    loadingDiv.style.cssText = 'background: #ff9800; color: white; padding: 10px; margin: 5px 0; border-radius: 4px; font-weight: bold; text-align: center; font-size: 13px;';
    loadingDiv.textContent = totalChunks > 0
        ? `⏳ Loading flows: 0/${totalChunks} chunks`
        : initialText;
    container.insertBefore(loadingDiv, container.firstChild);

    return loadingDiv;
}

/**
 * Update a progress indicator with new text and optionally change style.
 * @param {string} id - ID of the indicator element
 * @param {string} text - New text to display
 * @param {Object} options - { loaded, total, flowCount, isComplete }
 */
export function updateProgressIndicator(id, text, options = {}) {
    const { loaded, total, flowCount, isComplete = false } = options;
    const indicator = document.getElementById(id);

    if (!indicator) return;

    if (text) {
        indicator.textContent = text;
    } else if (loaded !== undefined && total !== undefined) {
        const progressText = flowCount !== undefined
            ? `⏳ Loading flows: ${loaded}/${total} chunks (${flowCount} flows)`
            : `⏳ Loading flows: ${loaded}/${total} chunks`;
        indicator.textContent = progressText;
    }

    if (isComplete) {
        indicator.style.background = '#4caf50'; // Green for success
    }
}

/**
 * Remove a progress indicator after an optional delay.
 * @param {string} id - ID of the indicator element
 * @param {number} delay - Delay in ms before removal (0 = immediate)
 */
export function removeProgressIndicator(id, delay = 0) {
    const remove = () => {
        const indicator = document.getElementById(id);
        if (indicator && indicator.parentNode) {
            indicator.remove();
        }
    };

    if (delay > 0) {
        setTimeout(remove, delay);
    } else {
        remove();
    }
}

/**
 * Show completion message on indicator then remove after delay.
 * @param {string} id - ID of the indicator element
 * @param {string} message - Completion message
 * @param {number} delay - Delay before removal (default 2000ms)
 */
export function showCompletionThenRemove(id, message, delay = 2000) {
    updateProgressIndicator(id, message, { isComplete: true });
    removeProgressIndicator(id, delay);
}
