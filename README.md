# IOC Investigator

IOC Investigator checks indicators with VirusTotal, AbuseIPDB and urlscan.io. It runs on Windows and Linux with Python 3.

## Setup

Create a virtual environment in the project folder.

Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
```

Create a `.env` file in the same folder as `ioc_tool.py`. Add the API keys for the services you want to use:

```text
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
URLSCAN_API_KEY=your_key
```

Keys are optional, but a service without a key will be skipped. `.env` is excluded from Git; keep your keys private.

## Run

Start the prompt:

```bash
python3 ioc_tool.py
```

On Windows, use `py ioc_tool.py`. Enter an IP address, domain, URL, SHA256 hash, or the path to a file. Examples:

```text
IOC: 8.8.8.8
IOC: example.com
IOC: https://example.com/login
IOC: /home/user/Downloads/sample.exe
```

For a file, the program calculates its SHA256 on your computer and checks whether VirusTotal has a report for that hash. It does not upload or scan the file. If no report exists, the verdict is `UNKNOWN`.

Type `exit`, `quit` or `bye` to close the prompt. Ctrl+C also stops the program. To check one indicator without the prompt, pass it on the command line:

```bash
python3 ioc_tool.py 8.8.8.8
```

Add `--json` to print the results as JSON. The verdict is a simple summary of available results, not a final security decision. Indicators sent to these services may be retained by them, so only submit information you are allowed to share.
