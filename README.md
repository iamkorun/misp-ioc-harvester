# 🛡️ MISP Threat Intel Harvester

A powerful Python tool for extracting and analyzing Indicators of Compromise (IOCs) from MISP (Malware Information Sharing Platform) instances. Features beautiful colored output, progress tracking, and comprehensive IOC analysis.

## ✨ Features

- 🔍 **Smart IOC Extraction** - Extracts IOCs from both events and attributes
- 🎨 **Beautiful CLI Interface** - Colored output with progress bars and icons
- 📊 **Comprehensive Analysis** - IOC type distribution and statistics
- 🔄 **Deduplication** - Automatic removal of duplicate IOCs
- 💾 **CSV Export** - Clean CSV output for further analysis
- ⚙️ **Flexible Configuration** - Environment-based configuration
- 🛡️ **Security First** - Sensitive data in environment variables

## 🚀 Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/misp-threat-intel-harvester.git
   cd misp-threat-intel-harvester
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your MISP credentials
   ```

4. **Run the harvester**
   ```bash
   python index.py
   ```

## ⚙️ Configuration

Create a `.env` file with your MISP configuration:

```env
MISP_URL=https://your-misp-instance.com
MISP_API_KEY=your-api-key-here
MISP_VERIFY_CERT=False
MISP_DAYS_BACK=7
MISP_EVENT_SEARCH=True
```

## 📊 Supported IOC Types

- IP addresses (source/destination)
- Domain names and hostnames
- URLs
- File hashes (MD5, SHA1, SHA256)
- Filenames

## 🛠️ Requirements

- Python 3.7+
- MISP instance with API access
- Network connectivity to MISP server

## 📄 Output

The tool generates:
- `misp_iocs.csv` - All extracted IOCs
- `debug_events.json` - Debug information (if enabled)
- Colored console output with progress tracking

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📝 License

MIT License - see LICENSE file for details

## 🔐 Security

- Never commit API keys or sensitive configuration
- Use environment variables for all credentials
- Verify SSL certificates in production environments

## 🐛 Troubleshooting

- Check MISP API key permissions
- Verify network connectivity to MISP instance
- Ensure Python dependencies are installed
- Check MISP server status and availability
