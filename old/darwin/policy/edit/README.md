# Policy editing
From this page, you can edit your Darwin Policies.  
Remember that the policies you create correspond to **use-cases** of detection: 
try to organize them as logical groups of filters to detect specific threats (DGA, flux variation, network scanning...)

# Name
This field represents the name of your policy.  
This name must be unique among your policies, but may contain any character.  
This will be the reference shown when assigning policies to **[Listeners](/services/frontend/)**.

# Description
This field can contain a more complete description of your policy.  
This description can help you clarify the role of a policy.

# Filters
This is the main part of this page, here you can set up the filters contained in your policy.  
The first part lists your filters currently in your policy:
- you can easily enable/disable them with the switch on the left
- the first button on the right allows you to edit a specific filter
- the second button on the right is to delete the filter completely
The second part allows you to add specific filters to the policy.

## Filter edition
### Filter type
To add/modify a filter, the first step is to select the type of filter you want.  
The current list of filters available is (you can get additional information by clicking on the name):
- **<a href="https://github.com/VultureProject/darwin/wiki/Filter-DGA" target="_blank">DGAD</a>**: this filter detects **Domain Generated Algorithms**, it takes domains found in network captures or logs. _This is a commercial filter and is not installed on Vulture by default._
- **<a href="https://github.com/VultureProject/darwin/wiki/Filter-Anomaly" target="_blank">UNAD</a>**: this filter detects **anomalies in network connections**, it can raise alerts when **IPs have an abnormal number of connections/open ports**. It is efficient at **detecting network scanners**, but can generate some false-positives. It takes network connection info from network capture and logs.
- **<a href="https://github.com/VultureProject/darwin/wiki/Filter-Connection" target="_blank">CONN</a>**: this filter raises an alert when a **new connection** is opened with a **specific source/destination/port/proto**, then stores the connection as known for a configured amount of time. It can be useful in specific cases when a particular **restricted endpoint needs to be monitored** for new connections. It takes network connection info from network capture, logs or HTTP/TCP Vulture Listeners.
- **<a href="https://github.com/VultureProject/darwin/wiki/Filter-Hostlookup" target="_blank">LKUP</a>**: this filter looks into databases for **Indicators Of Compromise** (IOCs), it currently uses Vulture's **[Context Tags](apps/reputation_ctx) databases** to detect malicious IPs, hostnames/domain names or hashes. It takes IPs from network capture or HTTP/TCP Listeners, or domain/host names and hashes from logs.
- **<a href="https://github.com/VultureProject/darwin/wiki/Filter-Sofa" target="_blank">SOFA</a>**: this filter **detects "outliers"** in network scans results. It cannot be used in continuous analysis scenarios, but must be made available with a workflow (unix server backend) to be synchronously called from outside Vulture. _This is a commercial filter and is not installed on Vulture by default._ 
- **<a href="https://github.com/VultureProject/darwin/wiki/Filter-Yara" target="_blank">YARA</a>**: this filter uses the **Yara engine** to raise alerts depending on **yara policies** setup in the **[Inspection Engine](/inspection/) section**. It mainly takes the data part from network captures to be scanned.

### Enabled
You can **enable or disable** a filter inside a policy. This can be useful to temporarily stop a specific algorithm, or to test new ones.  
**Some filters might not be installed on your system**, in that case enabling them will set the switch to red. This means the filter won't be started now, but will be automatically if you install it later.

### Threshold
**All filters generate a score** for a specific entry, some generate **either 0 or 100** (YARA or LKUP if an entry matches a rule or is in a database), others can generate a **number between 0 and 100** (DGAD for example).  
This parameter allows to filter out scores strictly below the threshold as alerts, this allows to **only raise alerts when the score is equal or above the configured threshold**. A good default is 80 to 90, depending on your false-positives acceptance.

### Log Level
This determines the log level of the Darwin filters.  
Valid levels are:
- Debug
- Informational
- Warning
- Error
- Critical

### Number of threads
This determines the **number of threads that will run** for this filter.  
It can **improve the performances of detection**, but **too much threads will be counter-productive**.  
A safe start is to **keep the default configuration**.

### Cache Size
Some filters can profit from an **internal cache** to **speed up consecutive hits** with the same entry (DGA for example).  
This parameter allows to configure the number of entries to be cached. entries will be flushed using a **<a href="https://en.wikipedia.org/wiki/Page_replacement_algorithm#Least_recently_used" target="_blank">Least Recently Used</a>** algorithm.

### Override Rsyslog Inputs
This is an **advanced** parameter, only use it when you know what you're doing!  
By default, **all Vulture Listeners have a list of compatible fields to send to each Darwin Filter**, this goes a step farther for Log Listeners with each log type having its own compatible fields.  
These lists allow to use those fields **automatically** when a **specific Darwin Filter** is assigned to a **specific Listener**. For example, a UNAD filter assigned to an IMPCAP Listener (through a configured Darwin Policy) will automatically take the correct Rsyslog fields generated by the impcap module (used for network capture) to send to the UNAD filter. This also means that **assigning a Listener to an incompatible filter will result in alerts never being raised** by it, as no data will be sent to it.  
**If this parameter is enabled** a list of **custom fields can be entered**, this list will **replace any default fields** that should otherwise be used with a specific Listener for this filter, meaning **the fields will be the same whatever the Listener may be**! As such, specific policies should be prefered for these cases, to avoid setting up specific fields for generic use-cases.  
The fields should be valid Rsyslog configuration variables, see **[the documentation](https://www.rsyslog.com/doc/v8-stable/rainerscript/variable_property_types.html)** for more information.

### Additional Rsyslog enrichment tags
When a Listener is assigned to a Darwin Policy with the **enrich logs and generate alerts** mode, **tags can potentially be added to the log line** if the returned score is above or equal to the configured threshold. **Alerts are also generated by Darwin** whatever the mode might be, and **tags will also be present in them**.  
In all these cases, **the tags added to logs or put in alert messages can be modified with this list**: all tags present here will be added to custom tags to be added to alerts and potential log enrichments.

### Continuous Analysis
Some filters require a batch of entries to correctly analyse and generate alerts, this is the case for example for UNAD.  
In this case, **Continuous Analysis** can be enabled on these filters to "cache" each entry received during a time lapse to be sent as a batch after a certain amount of time.  
Thanks to that, those filters can still be called synchronously with a batch of data when an analysis is required by external tools, but can also work on data received continuously from constant sources (logs, network captures, etc...).  
When cached, cache pools are separated for each filter and each source, meaning the same filter assigned to several Listeners won't receive a batch containing cache of all Listeners but of each Listener independently.  
The Continuous Analysis has 2 parameters:
- **Analysis Frequency**: the number of seconds to cache data before releasing it
- **Minimum batch size**: an (exclusive) batch size with which not to send the batch created (example: parameter is 10 and there are 9 entries cached = batch won't be sent, 10+ entries batch will be sent)


### Custom fields
Some filters can have custom parameters depending on their algorithm.

#### CONN
The CONN filter has 1 custom parameter:
- **Redis expire**: sets the duration to keep an existing connection as active, once this duration is spent the connection is considered new and will generate an alert if encountered. the parameter can be set to zero to disable expiration.

#### LKUP
The LKUP filter has 1 custom parameter:
- **Database**: The database file to use when searching for entries, this corresponds to a __[Context Tag](/apps/reputation_ctx)__ list.

#### YARA
The YARA filter has 3 custom parameters:
- **Fast Mode**: speeds up detection by not searching a rule again once it has matched.
- **Timeout**: the maximum number of seconds to wait for a scan to finish (zero means wait indefinitely)
- **Rule file list**: the list of __[yara policies](/darwin/inspection/)__ to use during detection