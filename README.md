# Mandiant Threat Intelligence for Splunk SOAR

## Configuration
1. Navigate to Apps, then locate Mandiant Threat Intelligence.  If it has not been previously configured, it will be
located under "Unconfigured Apps"
2. Click "Configure New Asset", then fill in the Name and Description fields
3. Under "Asset Settings", fill in your API Key and Secret Key for Mandiant TI
4. Click "Save"

## Commands

### lookup indicator
Retrieve indicators based on a given value.  Accepts URLs, FQDNs, IP addresses, and file hashes

### lookup threat actor
Retrieve information about a Threat Actor.  Accepts a "Mandiant ThreatActor"

### lookup vulnerability
Retrieve information about a Vulnerability.  Accepts a "CVE ID" or "Mandiant Vulnerability"

### lookup malware family
Retrieve information about a Malware Family.  Accepts a "Mandiant MalwareFamily"

### lookup report
Retrieve and display a Mandiant Report.  Accepts a "Mandiant Report"

### list reports
Retrieve a list of reports based on a given date range and an optional Report Type filter.

### search mandiant
Searches the Mandiant TI API for a given string