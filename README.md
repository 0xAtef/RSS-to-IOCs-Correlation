# RSS-to-IOCs Correlation

RSS-to-IOCs Correlation is a Python-based tool that collects, processes, and correlates Indicators of Compromise (IOCs) from RSS feeds. This project is designed to automate the extraction of threat intelligence data and store it in a format compatible with MISP (Malware Information Sharing Platform).

---

## Key Features
- **RSS Feed Monitoring**: Automatically fetches RSS feeds to collect IOCs.
- **IOC Processing**: Extracts, enriches, and categorizes IOCs from the feeds.
- **MISP-Compatible Output**: Generates CSV files formatted for MISP ingestion.
- **Feed Health Monitoring**: Ensures RSS feeds are healthy and accessible.
- **Customizable Configuration**: Fully configurable via JSON and environment variables.

---

## Installation

Follow these steps to set up the project:

### Prerequisites
- Python 3.10 or higher
- pip (Python package manager)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/0xAtef/RSS-to-IOCs-Correlation.git
   cd RSS-to-IOCs-Correlation
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Configure environment variables:
   Create a `.env` file at the root directory and include:
   ```plaintext
   MISP_BASE_URL=http://example.com
   MISP_API_KEY=your_api_key_here
   MISP_VERIFY_SSL=true
   ```

4. Configure the `config.json` file:
   ```json
   {
     "feed_urls": ["https://example.com/rss-feed"],
     "max_days_old": 20,
     "max_workers": 5
   }
   ```

---

## Usage

### Running the Collector
To run the RSS-to-IOCs collector:
```bash
python rss_ioc_collector.py
```

### Output
The script generates:
- **CSV File**: Located in `misp_feed/feed.csv`.
- **JSON File**: Located in `output/output.json` containing all collected records.

---

## Contribution Guidelines

We welcome contributions! Please refer to the [contributing guidelines](docs/contributing.md) to get started.

### To contribute:
1. Fork this repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request with a clear description of your changes.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Documentation

For detailed documentation on setup, usage, and contribution, visit the `docs/` folder:
- [Setup Instructions](docs/setup.md)
- [Usage Guide](docs/usage.md)
- [Contribution Guidelines](docs/contributing.md)
- [Project Overview](docs/overview.md)