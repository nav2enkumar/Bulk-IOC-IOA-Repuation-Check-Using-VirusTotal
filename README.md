# Bulk IOC Analyzer
### Investigation is Made Easy!

![Banner](screenshots/ioc-analyzer-logo.png)

## Let's Understand
A GUI-based Python tool to perform **bulk reputation checks** for IOCs (Hashes, IPs, Domains) using the **VirusTotal** API. Paste lists of IOCs into the GUI, click *Start Analysis*, and get a polished, Investigation-ready Excel report with separate sheet for each IOC type along with the recommended actions.

---
📚 Author - **Naveen Kumar** — Your Cyber Friend

---

## What is this script for?
Bulk IOC Analyzer simplifies threat-hunting and triage by automating reputation lookups against VirusTotal for multiple IOCs at once. Rather than checking items one-by-one, analysts can paste bulk lists and generate a single Excel file containing structured results and recommended actions.

## Why this script is different from others?
- **GUI-based**: Friendly interface — no terminal required for pasting your IOCs.
- **Multi-IOC input**: Submit hashes, IPs, and Domains at once.
- **Excel output**: Professional, well formatted Excel workbook with separate sheets for each IOC type (Hashes, IPs, Domains).
- **Actionable**: Each IOC row includes a recommended **Action** (e.g., Block in EDR / Block in F/W / None).
- **Ready for reporting**: Color-coded highlights, auto column widths, and concise VT scores.
- **Minimal setup**: Pure Python + standard libraries (plus pandas, requests, openpyxl).

## Requirements
- Python 3.7 or newer
- VirusTotal API Key (mandatory)
- Network access to `https://www.virustotal.com/api/`

## Install dependencies
Clone the repo or download files, then run:
```bash
python -m pip install -r requirements.txt
```
## Example: Install dependencies
![Banner](screenshots/Example-1.png)

`requirements.txt` contains:

```
requests
pandas
openpyxl
```

## How to run?
```bash
python VirusTotal_Bulk_IOC_Reputation_Check.py
```
## Example: How to run?
![Banner](screenshots/Example-2.png)

### GUI Usage
1. Start the script (see command above).
2. Paste your **IOCs one per line** (no CSV support) into the respective boxes (masked entries are also accepted):
   - Hashes (MD5, SHA1, SHA256)
   - IP Addresses
   - Domains  
3. Enter your **VirusTotal API Key** in the top field.
4. Click **Start Analysis**.
5. A popup will confirm the name of the Excel file and location (it is the same direcotry from where the script is running).
6. Check the file saved in the disk.

```
IOC_Analysis_Results.xlsx
```
## Example: GUI Usage
![Banner](screenshots/Example-3.png)

## Output file format
- **IOC_Analysis_Results.xlsx** — three sheets:
  - `Hashes` — Category, SHA-256, VT Score, Action
  - `IPs` — Category, IP Address, Organization, Country, VT Score, Action
  - `Domains` — Category, Address, VT Score, Action
- Styling applied:
  - Header fill (green)
  - Center aligned
  - Malicious VT Scores and Actions highlighted in red
  - Auto column width
  - Category cells merged for readability

## Example: Output file format
![Banner](screenshots/Example-4.png)

## Key things to remember
- API Usage - VirusTotal **free tier**: ~**250 requests/day** (may change — check VirusTotal docs).
- If you need more throughput, add/rotate multiple API keys (simple trick: supply multiple keys and round-robin requests — NOT implemented by default).

## Security & Privacy
- **API Key**: Keep your VT API key secure.
- **Data storage**: The script writes output to the working directory. Remove sensitive files after use if required by policy.
- **Rate limiting**: Be mindful of API quotas to avoid throttling or temporary bans.

**Cheers, Happy Investigation**
