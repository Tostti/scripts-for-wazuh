# Custom SCA scan
This script will allow the user to manually get the results of SCA scans at any moment, regardless if they changed from the last scan. It will get the results and inject them to the manager.

# Usage
## Script
This script runs in python 3. It requires the next parameters:
- **user**: it is the username to access the Wazuh API.
- **passw**: it is the password to access the Wazuh API.
- **policyid**: it is id of the SCA policy from which we need the result. It can be one or more values.
- **group** (optional) : it is the group of agents that we need to scan. It can be one or more values If no value is passed, it will scan all the agents on the `default` group.
- **ip** (optional) : it is the IP of the manager's API. If no value is passed, it will be `localhost`.
- **port** (optional) : it is the port of the manager's API. If no value is passed, it will be `55000`.

Example:
```console
python3 custom-sca.py  --user wazuh --passw wazuh  --policyid cis_centos7_linux --group testgroup testgroup2
```

It is possible to configure this script to automatically run with Wazuh's `command` wodle. For example: 
```xml
<wodle name="command">
    <tag>custom-sca-scan</tag>
    <disabled>no</disabled>
    <command>/var/ossec/framework/python/bin/python3 /home/custom-sca/custom-sca.py --user wazuh --passw wazuh  --policyid cis_centos7_linux --group testgroup testgroup2</command>
    <interval>1h</interval>
    <ignore_output>yes</ignore_output>
    <run_on_start>yes</run_on_start>
    <timeout>10</timeout>
  </wodle>
```
Make sure that Wazuh have access to the directory where the script is located, and running permissions.

## Custom rules
To be able to see the alerts on the manager, it is needed to create one or more custom rules.  The `location` of the events is `custom_sca_scan`. With that, we can create for example the following rules:
```xml
  <rule id="100002" level="0">
    <description>Manual sca scan results</description>
    <location>custom_sca_scan</location>
  </rule>
  
  <rule id="100003" level="3">
    <if_sid>100002</if_sid>
    <description>Passed SCA from manual scan</description>
    <field name="custom_sca_scan.sca.result">^passed</field>
  </rule>
  
  <rule id="100004" level="5">
    <if_sid>100002</if_sid>
    <description>Failed SCA from manual scan</description>
    <field name="custom_sca_scan.sca.result">^failed</field>
  </rule>
```

The alerts will contain information about the policy and about the scanned agent
