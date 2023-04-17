[comment]: # "Auto-generated SOAR connector documentation"
# Mandiant Advantage Threat Intelligence

Publisher: Mandiant  
Connector Version: 1.0.1  
Product Vendor: Mandiant  
Product Name: Threat Intelligence for Splunk SOAR  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.5.0  

Integrate with Mandiant Threat Intelligence to pull the latest information about indicators

[comment]: # "File: README.md"
[comment]: # "Copyright (c) Mandiant, 2023"
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
## Mandiant Advantage Threat Intelligence

### Actions Configured

-   test connectivity
-   lookup indicator
-   lookup threat actor
-   lookup vulnerability
-   lookup malware family
-   lookup report
-   list reports
-   search Mandiant

**All commands require a configured asset with a valid Mandiant Advantage license**

#### lookup indicator

This will retrieve information about a given Indicator of Compromise from the Mandiant Advantage
API. This information can be used to pivot further and obtain additional information.

#### lookup threat actor

This will retrieve information about a given Threat Actor from the Mandiant Advantage API.

#### lookup vulnerability

This will retrieve information about a given CVE or vulnerability from the Mandiant Advantage API.

#### lookup malware family

This will retrieve information about a given Malware Family from the Mandiant Advantage API.

#### lookup campaign

This will retrieve information about a given Campaign from the Mandiant Advantage API.

#### lookup report

This will retrieve the contents of a given Mandiant report from the Mandiant Advantage API.

#### list reports

This will retrieve a list of reports from the Mandiant Advantage API, which can then be retrieved by
using the \`lookup report\` command.

#### search Mandiant

This will search the Mandiant Advantage API for the provided string and return all resources that
match.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Threat Intelligence for Splunk SOAR asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**api_key** |  required  | password | Mandiant Threat Intelligence API Key
**secret_key** |  required  | password | Mandiant Threat Intelligence API Secret Key
**base_url** |  optional  | string | Base URL for Mandiant Threat Intelligence API
**verify_server_cert** |  required  | boolean | Require SSL Verification

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[lookup indicator](#action-lookup-indicator) - Retrieve indicator information  
[lookup campaign](#action-lookup-campaign) - Retrieve campaign information  
[lookup threat actor](#action-lookup-threat-actor) - Retrieve threat actor information  
[lookup vulnerability](#action-lookup-vulnerability) - Retrieve vulnerability information  
[lookup malware family](#action-lookup-malware-family) - Retrieve malware family information  
[lookup report](#action-lookup-report) - Retrieve Mandiant report  
[list reports](#action-list-reports) - Retrieve Mandiant reports  
[search mandiant](#action-search-mandiant) - Search Mandiant Threat Intelligence  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup indicator'
Retrieve indicator information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**indicator** |  optional  | Indicator to look up | string |  `domain`  `hash`  `ip`  `md5`  `sha1`  `sha256`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.indicator | string |  `domain`  `hash`  `ip`  `md5`  `sha1`  `sha256`  `url`  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.data.\*.type | string |  |  
action_result.data.\*.confidence | numeric |  |  
action_result.data.\*.categories.\* | string |  |  
action_result.data.\*.attributed_associations.\*.name | string |  |  
action_result.data.\*.first_seen | string |  |  
action_result.data.\*.last_seen | string |  |  
action_result.data.\*.associated_md5 | string |  `hash`  `md5`  |  
action_result.data.\*.associated_sha1 | string |  `hash`  `sha1`  |  
action_result.data.\*.associated_sha256 | string |  `hash`  `sha256`  |    

## action: 'lookup campaign'
Retrieve campaign information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**campaign** |  optional  | Campaign to look up | string |  `mandiant campaign` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.campaign | string |  `mandiant campaign`  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.data.\*.id | string |  |  
action_result.data.\*.name | string |  |  
action_result.data.\*.type | string |  |  
action_result.data.\*.tools.\*.id | string |  |  
action_result.data.\*.tools.\*.name | string |  |  
action_result.data.\*.tools.\*.attribution_scope | string |  |  
action_result.data.\*.actors.\*.id | string |  |  
action_result.data.\*.actors.\*.iso2 | string |  |  
action_result.data.\*.actors.\*.name | string |  |  
action_result.data.\*.actors.\*.country_name | string |  |  
action_result.data.\*.actors.\*.last_updated | string |  |  
action_result.data.\*.aliases.actor.\* | string |  |  
action_result.data.\*.aliases.malware.\* | string |  |  
action_result.data.\*.aliases.campaign.\* | string |  |  
action_result.data.\*.malware.\*.id | string |  |  
action_result.data.\*.malware.\*.name | string |  |  
action_result.data.\*.malware.\*.last_seen | string |  |  
action_result.data.\*.malware.\*.first_seen | string |  |  
action_result.data.\*.malware.\*.attribution_scope | string |  |  
action_result.data.\*.reports.\*.id | string |  |  
action_result.data.\*.reports.\*.title | string |  |  
action_result.data.\*.reports.\*.version | string |  |  
action_result.data.\*.reports.\*.audience.\*.name | string |  |  
action_result.data.\*.reports.\*.audience.\*.license | string |  |  
action_result.data.\*.reports.\*.report_id | string |  |  
action_result.data.\*.reports.\*.report_type | string |  |  
action_result.data.\*.reports.\*.published_date | string |  |  
action_result.data.\*.reports.\*.attribution_scope | string |  |  
action_result.data.\*.industries.\*.id | string |  |  
action_result.data.\*.industries.\*.name | string |  |  
action_result.data.\*.industries.\*.last_seen | string |  |  
action_result.data.\*.industries.\*.first_seen | string |  |  
action_result.data.\*.industries.\*.attribution_scope | string |  |  
action_result.data.\*.short_name | string |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.campaign_type | string |  |  
action_result.data.\*.profile_updated | string |  |  
action_result.data.\*.vulnerabilities.\*.id | string |  |  
action_result.data.\*.vulnerabilities.\*.type | string |  |  
action_result.data.\*.vulnerabilities.\*.cve_id | string |  |  
action_result.data.\*.vulnerabilities.\*.attribution_scope | string |  |  
action_result.data.\*.target_locations.regions.\*.id | string |  |  
action_result.data.\*.target_locations.regions.\*.name | string |  |  
action_result.data.\*.target_locations.regions.\*.type | string |  |  
action_result.data.\*.target_locations.regions.\*.attribution_scope | string |  |  
action_result.data.\*.target_locations.countries.\*.id | string |  |  
action_result.data.\*.target_locations.countries.\*.name | string |  |  
action_result.data.\*.target_locations.countries.\*.type | string |  |  
action_result.data.\*.target_locations.countries.\*.attribution_scope | string |  |  
action_result.data.\*.target_locations.countries.\*.iso2 | string |  |  
action_result.data.\*.target_locations.countries.\*.region | string |  |  
action_result.data.\*.target_locations.countries.\*.sub_region | string |  |  
action_result.data.\*.target_locations.sub_regions.\*.id | string |  |  
action_result.data.\*.target_locations.sub_regions.\*.name | string |  |  
action_result.data.\*.target_locations.sub_regions.\*.type | string |  |  
action_result.data.\*.target_locations.sub_regions.\*.attribution_scope | string |  |  
action_result.data.\*.target_locations.sub_regions.\*.region | string |  |    

## action: 'lookup threat actor'
Retrieve threat actor information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**threat_actor** |  optional  | Threat actor to look up | string |  `mandiant threatactor` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.threat_actor | string |  `mandiant threatactor`  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.data.\*.id | string |  |  
action_result.data.\*.cve.\*.id | string |  |  
action_result.data.\*.cve.\*.cve_id | string |  |  
action_result.data.\*.cve.\*.attribution_scope | string |  |  
action_result.data.\*.name | string |  |  
action_result.data.\*.type | string |  |  
action_result.data.\*.tools.\*.id | string |  |  
action_result.data.\*.tools.\*.name | string |  |  
action_result.data.\*.tools.\*.attribution_scope | string |  |  
action_result.data.\*.aliases.\*.name | string |  |  
action_result.data.\*.aliases.\*.attribution_scope | string |  |  
action_result.data.\*.malware.\*.id | string |  |  
action_result.data.\*.malware.\*.name | string |  |  
action_result.data.\*.malware.\*.last_seen | string |  |  
action_result.data.\*.malware.\*.first_seen | string |  |  
action_result.data.\*.malware.\*.attribution_scope | string |  |  
action_result.data.\*.audience.\*.name | string |  |  
action_result.data.\*.audience.\*.license | string |  |  
action_result.data.\*.observed.\*.recent | string |  |  
action_result.data.\*.observed.\*.earliest | string |  |  
action_result.data.\*.reports.\*.id | string |  |  
action_result.data.\*.reports.\*.title | string |  |  
action_result.data.\*.reports.\*.version | string |  |  
action_result.data.\*.reports.\*.audience.\*.name | string |  |  
action_result.data.\*.reports.\*.audience.\*.license | string |  |  
action_result.data.\*.reports.\*.report_id | string |  |  
action_result.data.\*.reports.\*.report_type | string |  |  
action_result.data.\*.reports.\*.published_date | string |  |  
action_result.data.\*.reports.\*.attribution_scope | string |  |  
action_result.data.\*.observed.\*.attribution_scope | string |  |  
action_result.data.\*.locations.source.\*.region.id | string |  |  
action_result.data.\*.locations.source.\*.region.name | string |  |  
action_result.data.\*.locations.source.\*.region.attribution_scope | string |  |  
action_result.data.\*.locations.source.\*.country.id | string |  |  
action_result.data.\*.locations.source.\*.country.name | string |  |  
action_result.data.\*.locations.source.\*.country.attribution_scope | string |  |  
action_result.data.\*.locations.source.\*.sub_region.id | string |  |  
action_result.data.\*.locations.source.\*.sub_region.name | string |  |  
action_result.data.\*.locations.source.\*.sub_region.attribution_scope | string |  |  
action_result.data.\*.locations.target.\*.id | string |  |  
action_result.data.\*.locations.target.\*.iso2 | string |  |  
action_result.data.\*.locations.target.\*.name | string |  |  
action_result.data.\*.locations.target.\*.region | string |  |  
action_result.data.\*.locations.target.\*.sub_region | string |  |  
action_result.data.\*.locations.target.\*.attribution_scope | string |  |  
action_result.data.\*.locations.target_region.\*.id | string |  |  
action_result.data.\*.locations.target_region.\*.key | string |  |  
action_result.data.\*.locations.target_region.\*.name | string |  |  
action_result.data.\*.locations.target_region.\*.attribution_scope | string |  |  
action_result.data.\*.locations.target_sub_region.\*.id | string |  |  
action_result.data.\*.locations.target_sub_region.\*.key | string |  |  
action_result.data.\*.locations.target_sub_region.\*.name | string |  |  
action_result.data.\*.locations.target_sub_region.\*.region | string |  |  
action_result.data.\*.locations.target_sub_region.\*.attribution_scope | string |  |  
action_result.data.\*.industries.\*.id | string |  |  
action_result.data.\*.industries.\*.name | string |  |  
action_result.data.\*.industries.\*.last_seen | string |  |  
action_result.data.\*.industries.\*.first_seen | string |  |  
action_result.data.\*.industries.\*.attribution_scope | string |  |  
action_result.data.\*.intel_free | boolean |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.motivations.\*.id | string |  |  
action_result.data.\*.motivations.\*.name | string |  |  
action_result.data.\*.motivations.\*.attribution_scope | string |  |  
action_result.data.\*.last_updated | string |  |  
action_result.data.\*.is_publishable | boolean |  |  
action_result.data.\*.associated_uncs.\*.id | string |  |  
action_result.data.\*.associated_uncs.\*.name | string |  |  
action_result.data.\*.associated_uncs.\*.attribution_scope | string |  |  
action_result.data.\*.associated_uncs.\*.attribution_scope | string |  |  
action_result.data.\*.last_activity_time | string |  |    

## action: 'lookup vulnerability'
Retrieve vulnerability information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vulnerability** |  optional  | CVE ID to look up | string |  `mandiant vulnerability`  `cve` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.vulnerability | string |  `mandiant vulnerability`  `cve`  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.data.\*.id | string |  |  
action_result.data.\*.cwe | string |  |  
action_result.data.\*.type | string |  |  
action_result.data.\*.title | string |  |  
action_result.data.\*.cve_id | string |  |  
action_result.data.\*.sources.\*.url | string |  |  
action_result.data.\*.sources.\*.date | string |  |  
action_result.data.\*.sources.\*.source_name | string |  |  
action_result.data.\*.sources.\*.source_description | string |  |  
action_result.data.\*.analysis | string |  |  
action_result.data.\*.audience.\* | string |  |  
action_result.data.\*.exploits.\*.md5 | string |  |  
action_result.data.\*.exploits.\*.name | string |  |  
action_result.data.\*.exploits.\*.file_size | numeric |  |  
action_result.data.\*.exploits.\*.description | string |  |  
action_result.data.\*.exploits.\*.exploit_url | string |  |  
action_result.data.\*.exploits.\*.reliability | string |  |  
action_result.data.\*.exploits.\*.release_date | string |  |  
action_result.data.\*.exploits.\*.replication_urls.\* | string |  |  
action_result.data.\*.intel_free | boolean |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.risk_rating | string |  |  
action_result.data.\*.workarounds | string |  |  
action_result.data.\*.publish_date | string |  |  
action_result.data.\*.was_zero_day | boolean |  |  
action_result.data.\*.is_publishable | boolean |  |  
action_result.data.\*.vulnerable_cpes.\*.cpe | string |  |  
action_result.data.\*.vulnerable_cpes.\*.cpe_title | string |  |  
action_result.data.\*.vulnerable_cpes.\*.vendor_name | string |  |  
action_result.data.\*.vulnerable_cpes.\*.technology_name | string |  |  
action_result.data.\*.associated_actors.\*.id | string |  |  
action_result.data.\*.associated_actors.\*.name | string |  |  
action_result.data.\*.associated_actors.\*.aliases.\*.name | string |  |  
action_result.data.\*.associated_actors.\*.aliases.\*.attribution_scope | string |  |  
action_result.data.\*.associated_actors.\*.intel_free | boolean |  |  
action_result.data.\*.associated_actors.\*.description | string |  |  
action_result.data.\*.associated_actors.\*.last_updated | string |  |  
action_result.data.\*.executive_summary | string |  |  
action_result.data.\*.associated_malware.\*.id | string |  |  
action_result.data.\*.associated_malware.\*.name | string |  |  
action_result.data.\*.associated_malware.\*.aliases.\*.name | string |  |  
action_result.data.\*.associated_malware.\*.has_yara | boolean |  |  
action_result.data.\*.associated_malware.\*.intel_free | boolean |  |  
action_result.data.\*.associated_malware.\*.description | string |  |  
action_result.data.\*.associated_malware.\*.last_updated | string |  |  
action_result.data.\*.date_of_disclosure | string |  |  
action_result.data.\*.exploitation_state | string |  |  
action_result.data.\*.vulnerable_products | string |  |  
action_result.data.\*.available_mitigation.\* | string |  |  
action_result.data.\*.exploitation_vectors.\* | string |  |  
action_result.data.\*.observed_in_the_wild | boolean |  |  
action_result.data.\*.vendor_fix_references.\*.url | string |  |  
action_result.data.\*.vendor_fix_references.\*.name | string |  |  
action_result.data.\*.exploitation_consequence | string |  |  
action_result.data.\*.vendor_fix_references.\*.url | string |  |    

## action: 'lookup malware family'
Retrieve malware family information

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**malware_family** |  optional  | Malware family to look up | string |  `mandiant malwarefamily` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.malware_family | string |  `mandiant malwarefamily`  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.data.\*.id | string |  |  
action_result.data.\*.cve.\*.id | string |  |  
action_result.data.\*.cve.\*.cve_id | string |  |  
action_result.data.\*.name | string |  |  
action_result.data.\*.type | string |  |  
action_result.data.\*.yara.\* | string |  |  
action_result.data.\*.roles.\* | string |  |  
action_result.data.\*.actors.\*.id | string |  |  
action_result.data.\*.actors.\*.iso2 | string |  |  
action_result.data.\*.actors.\*.name | string |  |  
action_result.data.\*.actors.\*.country_name | string |  |  
action_result.data.\*.actors.\*.last_updated | string |  |  
action_result.data.\*.aliases.\*.name | string |  |  
action_result.data.\*.malware.\*.id | string |  |  
action_result.data.\*.malware.\*.name | string |  |  
action_result.data.\*.audience.\*.name | string |  |  
action_result.data.\*.audience.\*.license | string |  |  
action_result.data.\*.detections.\* | string |  |  
action_result.data.\*.industries.\*.id | string |  |  
action_result.data.\*.industries.\*.name | string |  |  
action_result.data.\*.intel_free | boolean |  |  
action_result.data.\*.description | string |  |  
action_result.data.\*.capabilities.\*.name | string |  |  
action_result.data.\*.capabilities.\*.description | string |  |  
action_result.data.\*.last_updated | string |  |  
action_result.data.\*.is_publishable | boolean |  |  
action_result.data.\*.operating_systems.\* | string |  |  
action_result.data.\*.last_activity_time | string |  |  
action_result.data.\*.inherently_malicious | numeric |  |    

## action: 'lookup report'
Retrieve Mandiant report

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**report_id** |  optional  | Report ID to look up | string |  `mandiant report` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.report_id | string |  `mandiant report`  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data | string |  |  
action_result.summary | string |  |    

## action: 'list reports'
Retrieve Mandiant reports

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**days** |  optional  | Days to retrieve reports from | numeric | 
**report_type** |  optional  | Report Type Filter | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.days | numeric |  |  
action_result.parameter.report_type | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data | string |  |  
action_result.summary | string |  |    

## action: 'search mandiant'
Search Mandiant Threat Intelligence

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**query** |  optional  | Search query | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.query | string |  |  
action_result.status | string |  |   success  failed 
action_result.message | string |  |  
summary.total_objects | numeric |  |  
summary.total_objects_successful | numeric |  |  
action_result.data | string |  |  
action_result.summary | string |  |  