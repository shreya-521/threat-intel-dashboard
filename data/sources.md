## Data Sources Used

All data in this project is sourced from **FREE, PUBLIC** threat intelligence platforms.
No dark web access was used or needed.

| Source | What We Used | Link |
|--------|-------------|------|
| **MITRE ATT&CK** | Threat actor profiles, TTPs, campaign data | https://attack.mitre.org |
| **CISA KEV** | Known exploited vulnerabilities, IOC advisories | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| **AlienVault OTX** | IOC feeds (IPs, domains, file hashes) | https://otx.alienvault.com |
| **NVD / CVE** | CVE vulnerability records | https://nvd.nist.gov |
| **PhishTank** | Phishing URLs | https://www.phishtank.com |
| **MalwareBazaar** | Malware file hashes | https://bazaar.abuse.ch |
| **HaveIBeenPwned** | Data breach statistics | https://haveibeenpwned.com |
| **Shodan** | Internet-facing device data | https://www.shodan.io |

## How to Get Real Data (Optional Enhancement)

### AlienVault OTX API (Free)
```python
import requests

API_KEY = 'your_free_api_key'
headers = {'X-OTX-API-KEY': API_KEY}

# Get recent IOCs
response = requests.get(
    'https://otx.alienvault.com/api/v1/pulses/subscribed',
    headers=headers
)
data = response.json()
```

### CISA KEV JSON Feed (No API key needed)
```python
import requests, json

url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
response = requests.get(url)
cve_data = response.json()
```

### MITRE ATT&CK (STIX/TAXII - No API key needed)
```python
from stix2 import MemoryStore
from attackcti import attack_client

client = attack_client()
all_groups = client.get_groups()  # Gets all APT group profiles
```
