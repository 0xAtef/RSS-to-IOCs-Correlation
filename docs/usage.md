# Usage Guide

This document explains how to use the RSS-to-IOCs Correlation project.

---

## Running the Script
Use the following command to start the RSS-to-IOCs collector:
```bash
python rss_ioc_collector.py
```

---

## Output Files

### 1. **CSV File**:
- Location: `misp_feed/feed.csv`
- Description: Contains IOCs formatted for MISP ingestion.

### 2. **JSON File**:
- Location: `output/output.json`
- Description: Contains all processed records in JSON format.

---

## Customizing Output
You can modify the configuration in `config/config.json` to customize:
- RSS feed URLs
- Maximum number of days for feed processing
- Number of concurrent workers