# ACSC Cyber Tools

The ACSC CyberTools Plugins are build upon the functionality of the Constellation data visualisation platform (https://www.constellation-app.com/).

# Enrichments
The enrichments that are available in these plugins are:
##### 1. Maxmind (https://maxmind.com)
  This geolocation service for IP addresses can be used in either a network or standalone mode.  
  To configure this go to the Setup > Options > CONSTELLATION > ACSC > Maxmind tab.
  To use in network mode, add in your Maxmind User Id and API key, to use is standalone mode, download the mmdb files from Maxmind and set the locations.  
  
##### 2. VirusTotal (https://virustotal.com)
  This plugin will return any details found in VirusTotal for the selected Hashes.
  To configure this go to the Setup > Options > CONSTELLATION > ACSC > VirusTotal tab, set your API Key here.
  
##### 3. CrowdStrike (https://crowdstrike.com)
  This plugin will return any details found in Crowdstrike for the selected Hashes, IPs, Domains and others.
  To configure this go to the Setup > Options > CONSTELLATION > ACSC > CrowdStrike tab, set your API details here.
  
##### 4. DomainTools (https://domaintools.com)
  This plugin return the Whois details for IPs and Domains.
  To configure this go to the Setup > Options > CONSTELLATION > ACSC > DomainTools tab, set your API details here.

##### 5. GreyNoise (https://greynoise.io)
  This plugin will show any details available from GreyNoise, this includes a categorisation of IP addresses, scan results and associated JA3's.
  To configure this go to the Setup > Options > CONSTELLATION > ACSC > GreyNoise tab, set your API details here.
  
##### 6. Intezer (https://intezer.com)
  This plugin will show any details available from Intezer, shows the details of the analysis of any files that match the seed Hashes.
  To configure this go to the Setup > Options > CONSTELLATION > ACSC > Intezer tab, set your API details here.

##### 7. Shodan (https://shodan.io)
  This plugin will show any details available from Shodan, this allows us to run adhoc queries as well as pivot of ips, domains, and certificates
  To configure this go to the Setup > Options > CONSTELLATION > ACSC > Shodan tab, set your API details here.

##### 8. URLhaus (https://urlhaus.abuse.ch)
  This plugin will show any details available from URLhaus.  This is a list of domains associated with malware distribution.  We can query using domains, ips,   hashes or code families.

# Importers
##### 1. STIX Importer
  The STIX importer is used to import STIX v 2.x files.
  
##### 2. JDBC Importer
  This importer allows us to add various JDBC driver libraries and then connect to the databases they support.  We are then able to enter SQL queries to select the data we want to import and map this in a similar fashion to the Structured File importer.
  
##### 3. Windows Log Importer
  This importer allows visualise various Windows event evtx log files.  A selection of events have been added to date, this will increase over time.
  
# Setup
These plugins are dependant on the constellation core repository (https://github.com/constellation-app/constellation).  Please clone this repository first and make sure that you add the cloned location to the ACSCCyberTools project properties.
This can be done by right clicking the module suite "ACSCCyberTools" and selecting Properties option, then choose Libraries and press the "Add Cluster" button.

# Copyright and License
© Commonwealth of Australia 2020
