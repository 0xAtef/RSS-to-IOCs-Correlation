# Project Overview

RSS-to-IOCs Correlation is a Python-based tool that automates the collection, processing, and correlation of Indicators of Compromise (IOCs) from RSS feeds.

---

## Purpose
The project aims to simplify the process of gathering threat intelligence data and converting it into a format compatible with the Malware Information Sharing Platform (MISP).

---

## Architecture
1. **RSS Feed Collector**:
   - Continuously monitors RSS feeds for new IOCs.

2. **IOC Processor**:
   - Extracts, enriches, and categorizes IOCs.

3. **Output Generator**:
   - Creates MISP-compatible CSV files and a JSON summary of records.

---

## Key Features
- Automatic feed health monitoring.
- Fully customizable configuration.
- MISP-compatible output for seamless integration.

For more details, see the [Usage Guide](usage.md).