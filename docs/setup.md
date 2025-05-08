# Setup Instructions

This guide will walk you through the setup process for the RSS-to-IOCs Correlation project.

---

## Prerequisites
1. Ensure you have Python 3.10 or higher installed.
2. Install pip (Python package manager).

---

## Installation Steps

### 1. Clone the Repository
```bash
git clone https://github.com/0xAtef/RSS-to-IOCs-Correlation.git
cd RSS-to-IOCs-Correlation
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables
Create a `.env` file at the root directory and include:
```plaintext
MISP_BASE_URL=http://example.com
MISP_API_KEY=your_api_key_here
MISP_VERIFY_SSL=true
```

### 4. Configure JSON Settings
Edit the `config/config.json` file to include your RSS feed URLs and other settings:
```json
{
  "feed_urls": ["https://example.com/rss-feed"],
  "max_days_old": 20,
  "max_workers": 5
}
```

---

## Testing the Setup
Run the following command to confirm the setup is complete:
```bash
python rss_ioc_collector.py
```

If everything is set up correctly, the script will process the feeds and generate output files in the `misp_feed` and `output` directories.