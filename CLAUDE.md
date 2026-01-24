# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **dual-visualization network traffic analysis system** built with D3.js v7 for analyzing TCP packet data and attack patterns. It provides two complementary views:

1. **Network TimeArcs** (`attack_timearcs.html` → `attack_timearcs2.js`) - Arc-based visualization of attack events over time with force-directed IP positioning
2. **TCP Connection Analysis** (`ip_bar_diagram.html` → `ip_bar_diagram.js`) - Detailed packet-level visualization with stacked bar charts and flow reconstruction

## Running the Application

This is a static HTML/JavaScript application. Serve the directory with any HTTP server:

```bash
# Python 3
python -m http.server 8000

# Node.js (npx)
npx serve .

# Then open:
# http://localhost:8000/attack_timearcs.html  (TimeArcs view)
# http://localhost:8000/ip_bar_diagram.html   (TCP Analysis view)
```

The `index.html` redirects to `attack_timearcs.html` by default.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Main Visualizations                                     │
│  attack_timearcs2.js (~3900 LOC) - Arc network view      │
│  ip_bar_diagram.js (~4600 LOC)   - Packet analysis view  │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────┐
│  Supporting Modules                                      │
│  sidebar.js      - IP/flow selection UI                  │
│  legends.js      - Legend rendering                      │
│  overview_chart.js - Stacked flow overview + brush nav   │
│  folder_integration.js (~1300 LOC) - Folder data coord   │
│  folder_loader.js - Chunked folder data loading          │
│  viewer_loader.js - Viewer initialization utilities      │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────┐
│  /src Modular System (ES6 modules)                       │
│                                                          │
│  rendering/   bars.js, circles.js, arcPath.js, rows.js   │
│               arcInteractions.js, tooltip.js             │
│  scales/      scaleFactory.js, distortion.js (fisheye)   │
│  layout/      forceSimulation.js, barForceLayout.js      │
│  interaction/ zoom.js, dragReorder.js, resize.js         │
│  data/        binning.js, csvParser.js, flowReconstruction.js
│               resolution-manager.js, data-source.js      │
│               component-loader.js, csv-resolution-manager.js
│               aggregation.js, flow-loader.js             │
│               flow-list-loader.js (lazy CSV loading)     │
│  tcp/         flags.js (TCP flag classification)         │
│  groundTruth/ groundTruth.js (attack event loading)      │
│  mappings/    decoders.js, loaders.js                    │
│  workers/     packetWorkerManager.js                     │
│  plugins/     d3-fisheye.js                              │
│  ui/          legend.js                                  │
│  utils/       formatters.js, helpers.js                  │
│  config/      constants.js                               │
└──────────────────────────────────────────────────────────┘
```

### Key Data Flow

1. **CSV Input** → `csvParser.js` stream parsing OR folder-based chunked loading
2. **Packet Objects** → flow reconstruction, force layout positioning
3. **Ground Truth** → `groundTruth.js` loads attack event annotations from CSV
4. **Binning** → adaptive time-based aggregation (`binning.js`)
5. **Resolution Management** → `resolution-manager.js` handles zoom-level data with LRU caching
6. **Rendering** → stacked bars by flag type, arcs between IPs

**Flow Data for Overview Chart** (ip_bar_diagram.js:1703-1757):
- When IPs are selected, `updateIPFilter()` is called (async function)
- Uses adaptive multi-resolution loader (`flow_bins_index.json`) for efficient overview rendering
- Falls back to `flow_bins.json` or chunk loading if multi-resolution not available
- For v3 format (`chunked_flows_by_ip_pair`), filters chunks by IP pair first for efficiency
- Passes filtered/aggregated data to `overview_chart.js` for categorization and binning

### Worker Pattern

`packet_worker.js` handles packet filtering off the main thread:
- Receives packets via `init` message
- Filters by connection keys or IPs
- Returns `Uint8Array` visibility mask
- Managed by `src/workers/packetWorkerManager.js`

## Configuration

- `config.js` - Centralized settings (`GLOBAL_BIN_COUNT`, batch sizes)
- `src/config/constants.js` - Colors, sizes, TCP states

### JSON Mapping Files

- `full_ip_map.json` - IP address → descriptive name
- `attack_group_mapping.json` - Attack type → category
- `attack_group_color_mapping.json` - Category → color
- `event_type_mapping.json` - Event → color
- `flag_colors.json`, `flow_colors.json` - Visual styling

## Data Formats

**TimeArcs CSV**: `timestamp, length, src_ip, dst_ip, protocol, count`

**TCP Analysis CSV**: `timestamp, src_ip, dst_ip, src_port, dst_port, flags, length, ...`

**Folder-based data** (v3 format - `chunked_flows_by_ip_pair`):
```
packets_data/attack_flows_day1to5/
├── manifest.json              # Dataset metadata (version 3.0, format, totals, time range)
├── flows/
│   ├── pairs_meta.json        # IP pair index with per-pair chunk metadata
│   └── by_pair/               # Flows organized by IP pair (efficient filtering)
│       ├── 172-28-4-7__19-202-221-71/
│       │   ├── chunk_00000.json
│       │   ├── chunk_00001.json
│       │   └── ...
│       └── ...                # (574 IP pairs, 1318 total chunks)
├── indices/
│   ├── bins.json              # Time bins with total packet counts
│   ├── flow_bins.json         # Pre-aggregated flows by IP pair (single resolution)
│   ├── flow_bins_index.json   # Multi-resolution index for adaptive loading
│   ├── flow_bins_1s.json      # 1-second resolution bins (for zoomed views)
│   ├── flow_bins_1min.json    # 1-minute resolution bins
│   ├── flow_bins_10min.json   # 10-minute resolution bins
│   ├── flow_bins_hour.json    # Hourly resolution bins
│   └── flow_list/             # Flow summaries for flow list popup (lazy-loaded CSVs)
│       ├── index.json         # IP pair index with file references
│       └── *.csv              # Per-IP-pair CSV files (574 files, ~525MB total)
└── ips/
    ├── ip_stats.json          # Per-IP packet/byte counts
    ├── flag_stats.json        # Global TCP flag distribution
    └── unique_ips.json        # List of all IPs in dataset
```

**Legacy v2 format** (`chunked_flows`) also supported:
```
packets_data/attack_flows_day1to5_v2/
├── manifest.json          # version 2.2, format: chunked_flows
├── flows/
│   ├── chunks_meta.json   # Flat chunk index
│   ├── chunk_00000.json   # ~300 flows per chunk
│   └── ...
└── ...
```

The code auto-detects format from `manifest.json` and loads appropriately.

## Key Implementation Details

### Two Main Visualization Files

- `attack_timearcs2.js` (~3900 LOC) - Arc network view with force-directed IP layout
- `ip_bar_diagram.js` (~4600 LOC) - Detailed packet analysis with stacked bars

Both are monolithic files that compose modules from `/src`. They maintain extensive internal state (IP positions, selections, zoom state) and trigger re-renders on state changes.

### Overview Chart

The `overview_chart.js` module (~900 LOC) provides:
- Stacked bar overview of invalid flows by reason
- Brush-based time range selection synced with main chart zoom
- Legend integration for filtering by invalid reason/close type

**Current Implementation** (Multi-resolution adaptive loading):
- `ip_bar_diagram.js` initializes `AdaptiveOverviewLoader` from `flow_bins_index.json`
- Loader selects appropriate resolution based on visible time range (hour → 10min → 1min)
- Filters pre-aggregated flow bins by selected IP pairs
- Creates synthetic flows from bin data for overview chart
- **Fallback chain**: adaptive loader → `flow_bins.json` → chunk loading

**Multi-resolution index** (`flow_bins_index.json`):
```json
{
  "resolutions": {
    "1s": { "file": "flow_bins_1s.json", "bin_width_us": 1000000, "use_when_range_minutes_lte": 10 },
    "1min": { "file": "flow_bins_1min.json", "bin_width_us": 60000000, "use_when_range_minutes_lte": 120 },
    "10min": { "file": "flow_bins_10min.json", "bin_width_us": 600000000, "use_when_range_minutes_lte": 7200 },
    "hour": { "file": "flow_bins_hour.json", "bin_width_us": 3600000000, "use_when_range_minutes_gt": 7200 }
  }
}
```

**flow_bins.json Structure** (per resolution):
```json
[
  {
    "bin": 0,
    "start": 1257254652674641,
    "end": 1257258647167936,
    "flows_by_ip_pair": {
      "172.28.1.134<->152.162.178.254": {
        "graceful": 1,
        "abortive": 5,
        "invalid": {
          "rst_during_handshake": 290,
          "invalid_ack": 2,
          "incomplete_no_synack": 1
        },
        "ongoing": 10
      }
    }
  }
]
```

**Benefits**:
- **Adaptive resolution**: Coarse bins for overview, fine bins when zoomed
- **Instant loading**: Small files vs. thousands of chunk files
- **Efficient filtering**: Pre-aggregated by IP pair
- **Reduced memory**: No need to load full flow objects for overview

### Flow List CSV Files (Lazy Loading)

For deployments where chunk files are too large (e.g., GitHub Pages), generate per-IP-pair CSV files that contain flow summaries without packet arrays:

```bash
python packets_data/generate_flow_list.py --input-dir packets_data/attack_flows_day1to5
```

**Output Structure**:
```
indices/flow_list/
├── index.json                      # IP pair index (87KB)
├── 172-28-4-7__192-168-1-1.csv    # Flows for this IP pair
├── 172-28-4-7__10-0-0-1.csv       # Another IP pair
└── ...                             # 574 files total (~525MB)
```

**index.json Structure**:
```json
{
  "version": "1.1",
  "format": "flow_list_csv",
  "columns": ["src", "dst", "st", "et", "p", "sp", "dp", "ct", "ir"],
  "total_flows": 5482939,
  "total_pairs": 574,
  "unique_ips": 294,
  "time_range": { "start": 1257254652674641, "end": 1257654102004202 },
  "pairs": [
    { "pair": "172.28.4.7<->192.168.1.1", "file": "172-28-4-7__192-168-1-1.csv", "count": 1523 }
  ]
}
```

**CSV Format** (columns: src, dst, st, et, p, sp, dp, ct, ir):
```csv
src,dst,st,et,p,sp,dp,ct,ir
172.28.4.7,192.168.1.1,1257254652674641,1257254652800000,42,54321,80,graceful,
15.231.243.19,172.28.4.7,1257257931810544,1257257931810544,1,5085,80,invalid,incomplete_no_synack
```

**Lazy Loading Behavior**:
- On page load: Only `index.json` is fetched (~87KB)
- On IP selection: No CSV files loaded yet; UI shows "Flow List Available"
- On overview chart click: Only relevant IP pair CSVs are fetched for the clicked time range
- Loaded CSVs are cached in memory for subsequent requests

**Key Files**:
- `src/data/flow-list-loader.js` - FlowListLoader class for parsing/caching CSVs
- `src/data/flow-loader.js` - Decision tree that defers loading when FlowListLoader available

**When flow_list CSVs are present**:
- Flow list popup works without loading chunk files
- "View Packets" and "Export CSV" buttons are disabled (no packet data)
- Overview chart still uses adaptive flow_bins for visualization
- CSV format is ~45% smaller than JSON; all files under GitHub's 100MB limit

### Packet Data Multi-Resolution (v3.3)

The `csv-resolution-manager.js` handles zoom-level dependent packet data loading with 7 resolution levels:

| Resolution | Bin Size | Use When Visible Range |
|------------|----------|------------------------|
| hours | 1 hour | > 120 minutes |
| minutes | 1 minute | > 10 minutes |
| seconds | 1 second | > 1 minute |
| 100ms | 100ms | > 10 seconds |
| 10ms | 10ms | > 1 second |
| 1ms | 1ms | > 100ms |
| raw | individual packets | ≤ 100ms |

Coarse resolutions (hours, minutes, seconds) use single-file `data.csv` files loaded at initialization. Fine resolutions (100ms, 10ms, 1ms, raw) use chunked files loaded on-demand with LRU caching.

**Generating multi-resolution flow bins**:
```bash
# Generate all resolutions from existing v3 data
python packets_data/generate_flow_bins_v3.py --input-dir packets_data/attack_flows_day1to5
```

### Ground Truth Integration

`src/groundTruth/groundTruth.js` loads attack event annotations from `GroundTruth_UTC_naive.csv`:
- Parses event types, source/destination IPs, port ranges, time windows
- Converts timestamps to microseconds for alignment with packet data
- Filters events by selected IPs for contextual display

### Force-Directed Layout

- **TimeArcs**: Complex multi-force simulation with component separation, hub attraction, y-constraints
- **BarDiagram**: Simpler vertical ordering via `barForceLayout.js`

### Fisheye Distortion

The fisheye lens effect (`src/plugins/d3-fisheye.js`, wrapped by `src/scales/distortion.js`) provides overview+detail zooming. Controlled by the "Lensing" toggle and zoom slider in the UI.

### Performance Optimizations

- **Binning**: Reduces millions of packets to thousands of bins
- **Web Worker**: Packet filtering runs off main thread
- **Layer caching**: Full-domain layer pre-rendered
- **Batch processing**: Flow reconstruction and list rendering use configurable batch sizes
- **LRU Cache**: `resolution-manager.js` caches loaded detail chunks with automatic eviction
- **Multi-resolution loading**: Zoom-level dependent data loading (overview → detail)
- **IP-pair organization** (v3): Chunks organized by IP pair enable efficient filtering—only load chunks for selected IP pairs instead of scanning all chunks
- **Adaptive overview resolution**: Coarse bins for full view, fine bins when zoomed
- **Lazy flow list loading**: CSV files only loaded when user clicks overview chart bars

## Module Dependencies

Main files import heavily from `/src`:
- **Rendering**: `bars.js`, `circles.js`, `arcPath.js`, `rows.js`, `tooltip.js`, `arcInteractions.js`
- **Data**: `binning.js`, `flowReconstruction.js`, `csvParser.js`, `aggregation.js`, `resolution-manager.js`, `data-source.js`, `component-loader.js`
- **Layout**: `forceSimulation.js`, `barForceLayout.js`
- **Interaction**: `zoom.js`, `arcInteractions.js`, `dragReorder.js`, `resize.js`
- **Scales**: `scaleFactory.js`, `distortion.js`
- **Ground Truth**: `groundTruth.js`
- **Utils**: `formatters.js` (byte/timestamp formatting), `helpers.js`
- **UI**: `legend.js`
- **Config**: `constants.js` (colors, sizes, debug flags)

## Original TimeArcs Source

The `timearcs_source/` directory contains the original TimeArcs implementation for political blog analysis (unrelated to the network traffic visualization).
