I See You - Advanced Network Monitor
Developed by: Haider Kareem (حيدر كريم)
A powerful, real-time network monitoring application with advanced security assessment capabilities, multi-language support, and modern GUI design.
🚀 Features
Core Monitoring

Real-time Network Monitoring: Monitor all active network connections with live updates
Process Identification: Track which processes are making network connections
Connection Details: View local/remote addresses, ports, and connection status
Security Assessment: Advanced security scoring system for risk evaluation

Security Features

Digital Signature Verification: Check if executables are digitally signed (Windows)
Path Analysis: Assess security risk based on executable location
Port Security: Identify safe and dangerous ports
Admin Process Detection: Flag processes running with elevated privileges
Risk Classification: Automatic categorization (Safe/Medium/Risk)

User Interface

Multi-language Support: English, Arabic (RTL), and Russian
Dark/Light Themes: Toggle between terminal-style dark mode and clean light mode
Advanced Filtering: Regex-based search with security level filtering
Sortable Columns: Click any column header to sort data
Context Menus: Right-click for quick actions (copy, terminate, open location)

Data Management

CSV Export: Export filtered data to CSV files with timestamps
Real-time Updates: Configurable refresh intervals (200ms - 60s)
Connection Filtering: Show only established connections or all states
Performance Statistics: Monitor application performance and cache efficiency

📋 Requirements
System Requirements

Operating System: Windows 10+, Linux, macOS
Python: 3.8 or higher
RAM: 4GB minimum, 8GB recommended
Disk Space: 50MB

Python Dependencies
psutil>=5.9.0
PySide6>=6.5.0
jsonschema>=4.0.0
🛠️ Installation
Method 1: Clone and Install
bash# Clone the repository
git clone https://github.com/haiderkareem/iseeyou-network-monitor.git
cd iseeyou-network-monitor

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
Method 2: Direct Installation
bash# Install dependencies directly
pip install psutil PySide6 jsonschema

# Download and run
python main.py
🚀 Usage
Basic Usage
bash# Run the application
python main.py

# Run with administrator privileges (recommended for Windows)
# Right-click Command Prompt -> "Run as administrator"
python main.py
Command Line Options
bash# Run with custom config file
python main.py --config custom_settings.json

# Run in debug mode
python main.py --debug

# Show version information
python main.py --version
🎛️ Configuration
Settings File
The application creates a settings.json file with the following options:
json{
  "interval_ms": 1000,
  "only_established": true,
  "autostart": true,
  "lang": "en",
  "theme": "dark"
}
Configuration Options
OptionTypeDefaultDescriptioninterval_msinteger1000Update interval in milliseconds (200-60000)only_establishedbooleantrueShow only established connectionsautostartbooleantrueStart monitoring on application launchlangstring"en"Interface language (en/ar/ru)themestring"dark"UI theme (dark/light)
🔒 Security Features
Security Scoring Algorithm
The application uses a sophisticated scoring system:

Digital Signatures: +25 for valid, -15 for unsigned
System Paths: +15 for trusted locations
Temporary Directories: -20 for temp locations
Network Analysis: Bonus for private IPs, penalty for suspicious destinations
Port Assessment: +15 for HTTPS, penalties for dangerous ports
Process Privileges: -8 for admin processes

Risk Levels

🟢 Safe (75-100): Trusted processes with valid signatures
🟡 Medium (45-74): Standard processes with mixed indicators
🔴 Risk (0-44): Suspicious processes requiring attention

🌍 Language Support
Supported Languages

English - Full support with left-to-right layout
العربية (Arabic) - Complete RTL support with Arabic translations
Русский (Russian) - Full Cyrillic support

Adding New Languages
To add a new language:

Add language dictionary to I18N in main.py:

python'fr': {
    'app_title': "I See You — Moniteur Réseau Avancé",
    'start': "Démarrer",
    # ... add all keys
}

Update language selector in change_language() method
Test RTL support if needed

🎨 Themes
Dark Theme (Default)

Terminal-style green-on-black interface
Matrix-inspired color scheme
Optimized for extended monitoring sessions

Light Theme

Clean, modern interface
High contrast for daylight use
Color-coded security levels

📊 Performance
Optimization Features

Batch Processing: Connections processed in configurable batches
Smart Caching: LRU cache with TTL for signature verification
Memory Management: Automatic cleanup and resource management
Threading: Non-blocking UI with background monitoring

Performance Statistics
The application tracks:

Connections processed per second
Cache hit rates
Memory usage
Error rates

🔧 Troubleshooting
Common Issues
Permission Errors
bash# Windows: Run as Administrator
# Linux/macOS: Run with sudo
sudo python main.py
Missing Dependencies
bash# Install missing packages
pip install psutil PySide6 jsonschema
Performance Issues

Increase update interval in settings
Enable "Show only established connections"
Close other resource-intensive applications

Debug Mode
bash# Enable detailed logging
python main.py --debug

# Check log files
cat logs/network_monitor.log
Log Files
Logs are stored in logs/network_monitor.log with rotation:

Maximum file size: 10MB
Backup files: 5
Includes timestamps, function names, and line numbers

🤝 Contributing
Development Setup
bash# Fork the repository
git clone https://github.com/yourusername/iseeyou-network-monitor.git
cd iseeyou-network-monitor

# Create development environment
python -m venv dev-env
source dev-env/bin/activate  # or dev-env\Scripts\activate on Windows

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
Code Style

Follow PEP 8 guidelines
Use type hints
Add docstrings for all functions
Include unit tests for new features

Submitting Changes

Create a feature branch
Make your changes
Add tests
Update documentation
Submit a pull request

📜 License
This project is licensed under the MIT License - see the LICENSE file for details.
MIT License

Copyright (c) 2024 Haider Kareem

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
📞 Contact & Support
Developer Information

Name: Haider Kareem (حيدر كريم)
Email: haider.kareem@example.com
GitHub: @haiderkareem
LinkedIn: Haider Kareem

Support

Issues: GitHub Issues
Discussions: GitHub Discussions
Documentation: Wiki

🏆 Acknowledgments

psutil: Cross-platform process and system monitoring
PySide6: Qt6 Python bindings for modern GUI
jsonschema: JSON Schema validation
Community: Thanks to all contributors and users

📈 Roadmap
Version 2.1 (Planned)

 Network traffic visualization
 Export to multiple formats (JSON, XML)
 Database storage option
 Advanced alerting system

Version 2.2 (Future)

 Plugin system
 REST API interface
 Web dashboard
 Machine learning threat detection

Version 3.0 (Long-term)

 Distributed monitoring
 Cloud integration
 Mobile companion app
 Enterprise features


⭐ If you find this project useful, please give it a star on GitHub!
🐛 Found a bug? Report it here
💡 Have a feature request? Let us know
