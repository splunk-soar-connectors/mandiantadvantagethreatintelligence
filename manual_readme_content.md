## Mandiant Advantage Threat Intelligence

### Actions Configured

- test connectivity
- lookup indicator
- lookup threat actor
- lookup vulnerability
- lookup malware family
- lookup report
- list reports
- search Mandiant

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
