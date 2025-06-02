# WebGUI - Menu "Services / Listener settings"

From this view you can edit the settings of a specific frontend listener.

Multiple modes are available when creating a listener :

 - **TCP** : Create a TCP HAProxy frontend
 - **HTTP** : Create an HTTP HAProxy frontend
 - **LOG(Rsyslog)** : Create a TCP (Haproxy->Rsyslog) or a UDP (Rsyslog) or a Vendor Cloud API frontend LOG Listener
 - **LOG(Filebeat)** : Create a TCP (Haproxy->Filebeat) or a UDP (Filebeat) LOG Listener
 
Depending on which mode you chose, configuration settings differ.

## Global parameters

Some of the following configuration parameters are not used in some specific cases, mentionned for each of them.

`Enable listener` : You can enable or disable your listener.

`Friendly Name` : Here you can specify a friendly name for your listener. You cannot have multiple listeners with the same name.

`Enable logging` : This parameter is implicitly enabled in LOG mode.

You can enable or disable events forwarding. Mandatory if you want to select a [Logs Forwarder](../applications/logs_forwarder.md).

`Rsyslog Listening mode` : Here you chose a listening mode for your input :

 - **UDP** (listen logs with the Rsyslog imudp module)
 - **TCP** (listen logs with the Rsyslog imtcp module)
 - **TCP & UDP** (listen logs with Rsyslog imudp and imtcp module)
 - **RELP** (listen logs with Rsyslog imrelp module)
 - **FILE** (listen logs with Rsyslog imfile module)
 - **Vendor Specific API** (retrieve logs from external API events collect) 
 - **KAFKA** (collect logs from a kafka server, with Rsyslog imkafka module)
 - **REDIS** (collect logs from a redis server, with Rsyslog imhiredis module)

Depending on which listening mode you chose, configuration settings differs.
**See below for the specific configuration settings**

`Input logs type` : Here you can select the format of input logs, for example :

 - **generic_json** (json formatted logs)
 - **raw_to_json** (no specific format, but convert logs to json)

`Tags`: Tags used by file based parsers ([More infos](https://www.rsyslog.com/doc/configuration/modules/imfile.html#tag))


### Advanced Rsyslog parameters

By clicking the **Advanced** button on the lower right, the user will be able to further configure global (advanced) parameters for each Listener. Those options are better explained on [Rsyslog's documentation](https://www.rsyslog.com/doc/v8-stable/rainerscript/queue_parameters.html#queue-size)

`Size of mmdblookup cache`: Number of entries of the [LFU cache](https://en.wikipedia.org/wiki/Least_frequently_used) for mmdblookup.

`Type of queue` (default: *LinkedList*): Set a [queue type](https://www.rsyslog.com/doc/rainerscript/queue_parameters.html#queue-type) for the ruleset, valid values are:

 - **LinkedList** (queue with maximal size but dynamic allocation)
 - **FixedArray** (queue with fixed and preallocated size)
 - **Direct** (no queuing)

`Size of the queue` (default: *50000*): Maximum number of messages allowed in the action queue.

`Size of batch dequeue` (default: *1024*, must be less than the *size of the queue*): Maximum number of logs to use in a batch operation.

`Queue maximum workers` (default: *8*): Maximum number of workers to start for the action.

`Minimum messages to start a new worker` (default: *queue.size/queue.workerthreads*, must be less than the *size of the queue*): Every time this number of logs is reached in the queue size, a new worker will be started (for example, if set to 1000: a new worker will be started at 1000 logs waiting in queue, then 2000, then 3000...).

`Throttle input when queue reaches this size (between 1 and 99%)` (default: *70% of queue size*, must be between 1% and 99%, cannot be over the *Stop processing input logs when queue reaches this size (between 1 and 99%)* parameter below): Light delay mark, starts throttling queue to allow delayable inputs to be slowed, and to allow non-delayable inputs to be processed without losing logs. See [Rsyslog documentation](https://www.rsyslog.com/doc/rainerscript/queue_parameters.html#queue-lightdelaymark) for more details.

`Stop processing input logs when queue reaches this size (between 1 and 99%)` (default: *98% of queue size*, must be between 1% and 99%, cannot be under the *Throttle input when queue reaches this size (between 1 and 99%)* parameter above): Discard mark, starts discarding logs based on their severity when the queue size percent is reached. See [Rsyslog documentation](https://www.rsyslog.com/doc/rainerscript/queue_parameters.html#queue-discardmark) for more details.

`Queue timeout shutdown (ms)` (default: [*1500ms*](https://www.rsyslog.com/doc/rainerscript/queue_parameters.html#queue-timeoutworkerthreadshutdown), must be a strictly positive number): Number of milliseconds to wait before droping the remaining logs to process on the action.

---

`Enable disk queue on failure` (default: *false*): Use Disk-assisted Rsyslog queues to reliably keep logs on disk when accumulating in ruleset queue.

    Following parameters only applies to disk-assisted queues, *Enable disk queue on failure* must be enabled

 - `Low watermark target` (default: *70% of queue size*, must be between 1% and 99%, cannot be over the *High watermark target* parameter below): When writing to disk is triggered by the `High watermark target`, it will return to in-memory queueing when the amount of logs in it falls back under this value.

 - `High watermark target` (default: *90% of queue size*, must be between 1% and 99%, cannot be under the *Low watermark target* parameter above): When the queue reaches this amount of messages waiting in queue, Rsyslog will begin to spool on disk.

 - `Max file size of the queue in MiB` (default: *16MiB*, must be strictly positive): Maximum size of a single disk-assisted queue file, new files will be created to keep storing logs if previous ones become full, as long as total space limit is not reached (see *Max disk space used by the queue in MiB* parameter below).

 - `Max disk space used by the queue in MiB` (default: *0MiB (unlimited)*, must be positive or zero (meaning *no limit*)): Total maximum size for all files storing logs on a disk-assisted queue. Note that the total size may slightly exceed that value as logs are always written completely to disk.

 - `Update bookkeeping information every Nth entry` (default: *0 (disabled)*, must be positive): Update housekeeping information every Nth message saved on Disk-assisted queue, to ensure better reliability in case of failure. This will decrease queue performances but will ensure logs can be correctly recovered in case of hard failures, the value set will represent the number of messages that *could* be lost on failures.

 - `Folder to store queue files to` (default: */var/tmp*): Existing directory (**in the Rsyslog jail**) to write queue spool files to.

!!! warning
    The folder should be created prior to defining it here, and should be available in the **Rsyslog jail** (/zroot/rsyslog) !

---

`Disable Octet Counting Framing` : Here you specify the Rsyslog imtcp option "SupportOctetCountedFraming", this is an advanced option, enable the option only if you know what you are doing.

`rate-limiting interval` (default: *None*): Specifies the rate-limiting interval to take into account to trigger limiting (in seconds).

`rate-limiting burst` (default: *None*): Specifies the number of messages to receive during the *rate-limiting interval*, before triggering rate-limiting.

## Listeners

Listeners are not shown in LOG mode with listening mode Kafka, Redis or File. Indeed, there is no need to accept incoming trafic. Instead, Vulture will initiate a connection to the remote Databroker or read a local File to retrieve logs.

Here you can configure the listening, by configuring for each row the following parameters :

- **Listen address** : Select the IP address you want to listen on
- **Port** : Configure the port you want to listen on
- **TLS Profile** : Not supported for now in LOG mode, here you can select a [TLS Profile](../global_config/tls.md)
- **Allow from** : "Any" by default, configure a comma separated list of allowed IP addresses to connect from
- **Max src** : Configure a max number of source IP addresses allowed to connect
- **Max rate** : Configure a max rate

`Timeout connect` : Configure the allowed connect timeout (in ms) after which HAProxy will end new connection.

`Timeout client` : Set the maximum inactivity time on the client side.


## Logs Enrichment

`Tenants config` : This parameter is useless if you select a mode different of LOG or if you disable logging.

Here you can select a [Multi-tenants configuration](../global_config/tenant.md), that will be used to enrich logs and select enrichment databases.

`Enable reputation logging` : This parameter is useless if you select a mode different of LOG or if you disable logging.

Here you can enable or disable logs enrichment with Rsyslog, by configuring parameters below.

`Reputation database IPv4` : This parameter is useless if you select a mode different of LOG or if you disable logging.

Here you can select an [IPv4 MMDB database](../applications/cti_lookup.md) to enrich logs with source and destination IPv4 addresses informations (ex: reputation).

`Reputation database IPv6` : This parameter is useless if you select a mode different of LOG or if you disable logging.

Here you can select an [IPv6 MMDB database](../applications/cti_lookup.md) to enrich logs with source and destination IPv6 addresses informations (ex: reputation).

`GeoIP database (IPv4)` : This parameter is useless if you select a mode different of LOG or if you disable logging.

Here you can select an [GeoIP MMDB database](../applications/cti_lookup.md) to enrich logs with public source and destination IP addresses localization.

`Reputation contexts` : This parameter is useless if you select a mode different of LOG or if you disable logging.

Here you can configure more specificly the enrichment of logs by selecting and configuring 4 fields by row :

 - **Enabled** : Enable of disable the row
 - **IOC database** : Select the [reputation context](../applications/cti_lookup.md) to use
 - **Input field name** : Configure the field name to send to database
 - **Destination field name** : Configure the field name you want to stock the result into


## Logs Forwarder

This section is useless if you select a mode different of LOG or if you disable logging. You can here select Log forwarder(s).
If events are correctly parsed, depending on which ruleset is configured, they will be sent to this remote log forwarder.

See [Logs Forwarder](../applications/logs_forwarder.md) to define remote log repositories.


`Log condition (advanced)` : This parameter is useless if you select a mode different of LOG or if you disable logging.

You can here configure an Rsyslog custom configuration bloc. Only use this parameter if you know what your doing.
Using this interface you can rename parsed JSON field or add rsyslog's rainer script conditions on the log pipeline.

## Custom configuration

Via this tab, you may declare custom HAProxy directives. These directives will be placed within the [Frontend] section of HAProxy configuration file related to the current Listener.

## Specific settings for Rsyslog Listening Modes

### FILE listening mode specific parameters

`Node` : Configure the node on which you want to listen on file (or kafka or redis).

`File path` : Specify the absolute path of the file to listen on.

`Tags` : Specify one or multiple comma separated tag(s) to associate on your listener.

### KAFKA listening mode specific parameters

`Kafka Brokers` : Configure comma separated list of Kafka broker(s) to poll logs from.

`Kafka topic` : Configure kafka topic to poll logs from.

`Kafka consumer group` : Optional, configure the kafka consumer group to use to poll logs from.

### REDIS listening mode specific parameters

This listener relies on rsyslog / imhiredis, and has three modes of operation :

`Queue Mode, using push/pop` : The queue mode will LPOP or RPOP your message from a redis list.

Following parameters are required :

 - **Redis consumer mode** : Set mode to "queue" to enable the queue mode
 - **Redis key** : The key to xPOP on
 - **Redis server** : The name or IP address of the redis server (Vulture's Internal redis load-balancer is 127.0.0.5)
 - **Redis port** : The redis listening port (default is 6379)

Following parameters are optional :

 - **Redis password** : If set, the plugin will issue an "AUTH" command before calling xPOP
 - **Use LPOP** : If set to "on", LPOP will be used instead of default RPOP

When using the local Redis instance in the Cluster, you can simply select the **Use local redis** button to automatically set the correct parameters to access it. This will include the redirection to the current main Redis node of a cluster and the use of the Cluster password.

Redis pipelining is used inside the workerthread, with a hardcoded batch size of #10.

Imhiredis will query Redis every second to see if entries are in the list, if that's the case they will be dequeued continuously by batches of 10 until none remains.

Due to its balance between polling interval and pipelining and its use of lists, this mode is quite performant and reliable.
However, due to the 1 second polling frequency, one may consider using the `subscribe` mode instead if very low latency is required.

`Channel Mode, using pub/sub` : The channel mode will SUBSCRIBE to a redis channel.

The "key" parameter is required and will be used for the subscribe channel.

Following parameters are required :

 - **Redis consumer mode** : Set mode to "subscribe" to enable the subscribe mode
 - **Redis key** : The key to subscribe to (aka the "channel")
 - **Redis server** : The name or IP address of the redis server
 - **Redis port** : The redis listening port

Following parameters are optional :

 - **Redis password** : If set, the plugin will issue an "AUTH" command before listening to a channel

`Stream Mode, using xread/xreadgroup` : The stream mode will XREAD or XREADGROUP to a redis stream.

The "key" parameter is required and will be used to query the stream.

Following parameters are required :

 - **Redis consumer mode** : Set mode to "stream" to enable the stream mode
 - **Redis key** : The key to target the stream
 - **Redis server** : The name or IP address of the redis server
 - **Redis port** : The redis listening port

Following parameters are optional :

 - **Redis password** : If set, the plugin will issue an "AUTH" command before calling XREAD
 - **Redis stream consumer group** : The Consumer Group to use
 - **Redis stream consumer name** : The Consumer Name to use (mandatory when **Redis stream consumer group** is set)
 - **Redis stream start choice** : The specified starting ID for the stream, can be either
    - "**-**": From the beginning
    - "**$**": New entries
    - "**>**": Undelivered entries (only applicable to Consumer Groups)
 - **Acknowledge processed entries** : Send an acknowledge to Redis after reading (Only applicable to Consumer Groups)
 - **Reclaim pending messages (ms)** : Automatically reclaim pending messages after X milliseconds (Only applicable to Consumer Groups)


### Vendor Log API listening mode specific parameters

`API Parser Type` : Here you can chose the technology of events you want to retrieve api events from.

The following endpoints are supported :

 - FORCEPOINT
 - AWS BUCKET
 - SYMANTEC
 - AKAMAI
 - OFFICE 365
 - IMPERVA
 - REACHFIVE
 - MONGODB
 - DEFENDER ATP
 - CORTEX XDR
 - CYBEREASON
 - CISCO MERAKI
 - PROOFPOINT TAP
 - SENTINEL ONE
 - CARBON BLACK
 - NETSKOPE
 - RAPID7 IDR
 - HARFANGLAB
 - VADESECURE
 - DEFENDER
 - CROWDSTRIKE
 - VADESECURE O365
 - NOZOMI PROBE
 - BLACKBERRY CYLANCE
 - MS SENTINEL
 - PROOFPOINT POD
 - WAF CLOUDFLARE
 - GSUITE ALERTCENTER
 - SOPHOS CLOUD
 - TRENDMICRO WORRYFREE
 - SAFENET
 - PROOFPOINT CASB
 - PROOFPOINT TRAP
 - WAF CLOUD PROTECTOR
 - TRENDMICRO VISIONONE
 - CISCO DUO
 - SENTINEL ONE MOBILE
 - CSC_DOMAINMANAGER
 - RETARUS
 - VECTRA

`Use proxy` : Use proxy for requests (will use System Proxy if no `Custom Proxy` is configured)

`Custom Proxy` : Url of the proxy used by the API collector (system proxy if not set)

`Verify certificate` : Enable the verification of the certificates used by the API endpoint

`Custom certificate` : Provide a custom certificate previously added in the [X509 Certificates](../global_config/pki.md) menu

### Vendor Log API Forcepoint specific parameters

`Forcepoint host` : Beginning url of the forcepoint endpoint to retrieve events from. Logs will be collected from {forcepoint_host}/siem/logs.

`Forcepoint username` : Username to use to authenticate to Forcepoint API.

`Forcepoint password` : Password to use to authenticate to Forcepoint API.

### Vendor Log API AWS bucket specific parameters

`AWS Access Key Id` : Key ID to use to authenticate on AWS API endpoint.

`AWS Secret Access Key` : Secret key to use to authenticate on AWS API endpoint.

`AWS Bucket Name` : Bucket name to retrieve events from.

### Vendor Log API Symantec specific parameters

`Symantec username` : Username to use to authenticate on Symantec API endpoint.

`Symantec password` : Password to use to authenticate on Symantec API endpoint.

### Vendor Log API Akamai specific parameters

`Akamai Host` : Akamai domaine name to collect events from.

`Akamai Client Secret` : Client Secret to use to authenticate on Akamai API endpoint.

`Akamai Access Token` : Access Token to use to authenticate on Akamai API endpoint.

`Akamai Client Token` : Client Token to use to authenticate on Akamai API endpoint.

`Akamai Config ID` : Config ID to use to retrieve events from Akamai API endpoint.

### Vendor Log API Office365 specific parameters

`Office365 Tenant ID` : Tenant to use to collect events from Office365 API endpoint.

`Office365 Client ID` : Client ID to use to authenticate on Akamai API endpoint.

`Office365 Client Secret` : Client secret to use to authenticate on Akamai API endpoint.

### Vendor Log API Imperva specific parameters

`Imperva Base Url` : Base URL to use to collect events from. It should ends with a /.

`Imperva Api ID` : App ID to use to authenticate on Imperva API endpoint.

`Imperva Api Key` : Api secret to use to authenticate on Imperva API endpoint.

`Imperva Private Key` : Private Key to use to decrypt collected events from Imperva API endpoint.

### Vendor Log API ReachFive specific parameters

`ReachFive Host` : Host name to use to retrieve events from. Ex: reachfive.domain.com.

`ReachFive Client ID` : Client ID to use to authenticate on ReachFive API endpoint.

`ReachFive Client Secret` : Client Secret to use to authenticate on ReachFive API endpoint.

### Vendor Log API MongoDB (Atlas) specific parameters

`Mongodb API User` : User to use to authenticate on MongoDB API endpoint.

`MongoDB API Password` : Password to use to authenticate on MongoDB API endpoint.

`MongoDB API Group ID` : Group ID to use to retrieve events from MongoDB API endpoint.

### Vendor Log API Defender ATP specific parameters

`MDATP API Tenant` : Tenant ID to use to retrieve events from Defender ATP API endpoint.

`MDATP API App ID` : App ID to use to authenticate on Defender ATP API endpoint.

`MDATP API Secret` : Secret to use to authenticate on Defender ATP API endpoint.

### Vendor Log API Cortex XDR specific parameters

`Cortex XDR Host` : Host name to use to retrieve events from API endpoint.

    This parameter will be used as : https://api-{cortex_xdr_host}/public_api/v1/

`Cortex XDR API Key ID` : API Key ID to use to authenticate on API endpoint.

`Cortex XDR API Key` : API Key to use to authenticate on API endpoint.

### Vendor Log API Cybereason specific parameters

`Cybereason Host` : Base URL (with scheme) to use to retrieve events from Cybereason API endpoint.

`Cybereason Username` : Username to use to authenticate on Cybereason API endpoint.

`Cybereason Password` : Password to use to authenticate on Cybereason API endpoint.

### Vendor Log API Cisco Meraki specific parameters

`Cisco Meraki API Key` : API Key to use to authenticate on Cisco Meraki API endpoint.

### Vendor Log API Proofpoint TAP specific parameters

`Proofpoint TAP Host` : Base URL to use to retrieve events from Proofpoint TAP API endpoint.

    Ex: https://tap-api-v2.proofpoint.com

`Proofpoint TAP Endpoint` : Kind of events to retrieve from Proofpoint TAP endpoint :

 - all (/all)
 - clicks/blocked (/clicks/blocked)
 - clicks/permitted (/clicks/permitted)
 - messages/blocked (/messages/blocked)
 - messages/delivered (/messages/delivered)
 - issues (/issues)

`Proofpoint TAP Principal` : Principal (username) to use to authenticate on Proofpoint API endpoint.

`Proofpoint TAP Secret` : Secret (password) to use to authenticate on Proofpoint API endpoint.

### Vendor Log API SentinelOne specific parameters

`SentinelOne Host` : Hostname (without scheme or path) of the SentinelOne server.

`Sentinel One API key` : API key used to retrieve logs - as configured in SentinelOne settings.

`Sentinel One Account type` : Type of account : console or user service.

### Vendor Log API CarbonBlack specific parameters

`CarbonBlack Host` : Hostname (without scheme or path) of the CarbonBlack server.

`CarbonBlack organisation name` : Organisation name.

`CarbonBlack API key` : API key used to retrieve logs.

### Vendor Log API Netskope specific parameters

`Netskope Host` : Hostname (without scheme or path) of the Netskope server.

`Netskope API token used to retrieve events` : Netskope API token.

### Vendor Log API Rapid7 IDR specific parameters

`rapid7 IDR Host` : Hostname (without scheme or path) of the Rapid7 server.

`Rapid7 IDR API key` : API key used to retrieve logs.

### Vendor Log API HarfangLab specific parameters

`HarfangLab Host` : Hostname (without scheme or path) of the HarfangLab server.

`HarfangLab API key` : API key to use to contact HarfangLab api.

### Vendor Log API Vadesecure specific parameters

`Vadesecure Host` : Hostname (without scheme or path) of the Vadesecure server.

`Vadesecure login` : Login used to fetch the token for the Vadesecure API.

`Vadesecure password` : Password used to fetch the token for the Vadesecure API.

### Vendor Log API Defender specific parameters

`Defender token endpoint` : Complete enpoint address to get an Oauth token before requesting Microsoft's APIs.

`Defender OAuth client id` : Client id of the OAuth endpoint to get an OAuth token before requesting Microsoft's APIs.

`Defender OAuth client secret` : Client secret of the OAuth endpoint to get an OAuth token before requesting Microsoft's APIs.

### Vendor Log API CrowdStrike specific parameters

`CrowdStrike Host` : Complete enpoint address.

`CrowdStrike Username` : User's name.

`CrowdStrike Client ID` : Client ID used for authentication.

`CrowdStrike Client's Secret` : Client's secret used for authentication.

### Vendor Log API Vadesecure 0365 specific parameters

`Vadesecure O365 Host` : FQDN of the API endpoint.

`Vadesecure O365 tenant` : Tenant.

`Vadesecure O365 Client ID` : Client ID used for authentication.

`Vadesecure O365 Client's Secret` : Client's secret used for authentication.

### Vendor Log API Nozomi Probe specific parameters

`Nozomi Probe Host` : Hostname (without scheme or path) of the Nozomi Probe.

`Nozomi Probe User` : User to use to contact Nozomi probe api.

`Nozomi Probe Password` : Password to use to contact Nozomi probe api.

### Vendor Log API Blackberry Cylance specific parameters

`Blackberry Cylance Host` : FQDN of the API endpoint.

`Blackberry Cylance tenant` : Tenant.

`Blackberry Cylance Application ID` : Client ID used for authentication.

`Blackberry Cylance Application's Secret` : Client's secret used for authentication.

### Vendor Log API Microsoft Sentinel specific parameters

`Microsoft Sentinel Tenant ID` : Your Microsoft Tenant ID.

`Microsoft Sentinel App ID` : Microsoft Sentinel Client ID.

`Microsoft Sentinel App Secret` : Application Secret.

`Microsoft Sentinel Subscription ID` : Subscription ID.

`Microsoft Sentinel Resource Group` : Resource Group name.

`Microsoft Sentinel Workspace` : Workspace name.

### Vendor Log API Proofpoint PoD specific parameters

`Proofpoint PoD URI` : Server URI.

`Proofpoint PoD Cluster ID` : Cluster ID.

`Proofpoint PoD Authentication token` : Authentication token.

### Vendor Log API WAF Cloudflare specific parameters

`WAF Cloudflare API token` : WAF Cloudflare  API token.

`WAF Cloudflare zone ID` : WAF Cloudflare zone ID.

### Vendor Log API Google worspace alertcenter specific parameters

`Google Alertcenter JSON Conf` : Your JSON Conf from Google.

`Google Alertcenter Admin email for delegated wrights` : Google Alertcenter Admin email.

### Vendor Log API Sophos Cloud specific parameters

`Sophos Cloud - Client ID` : Client ID.

`Sophos Cloud - Client Secret` : Client Secret.

`Sophos Cloud - Tenant ID` : Tenant ID.

### Vendor Log API Trendmicro_worryfree specific parameters

`Trendmicro Worryfree access token` : Trendmicro Worryfree access token.

`Trendmicro Worryfree secret key` : Trendmicro Worryfree secret key.

`Trendmicro Worryfree server name` : Trendmicro Worryfree server name.

`Trendmicro Worryfree server port` : Trendmicro Worryfree server port.

### Vendor Log API Safenet specific parameters

`Safenet Tenant Code` : Your Safenet Tenant Code.

`Safenet API Key` : Safenet Token API.

### Vendor Log API Proofpoint CASB specific parameters

`Proofpoint CASB API KEY` : Proofpoint CASB API KEY.

`Proofpoint CASB Client ID` : Proofpoint CASB Client ID.

`Proofpoint CASB Client Secret` : Proofpoint CASB Client Secret.

### Vendor Log API Proofpoint TRAP specific parameters

`ProofPoint TRAP host` : ProofPoint API root url.

`ProofPoint TRAP API key` : ProofPoint TRAP API key.

### Vendor Log API WAF Cloud Protector specific parameters

`WAF CloudProtector host` : Hostname (without scheme or path) of the CloudProtector server.

`WAF CloudProtector public key` : base64 encodid public key to contact CloudProtector API.

`WAF CloudProtector private key` : base64 encodid private key to contact CloudProtector API.

`WAF Cloud Protector provider` : Provider used to retrieve event from.

`WAF Cloud Protector tenant` : Tenant used to retrieve event from.

`WAF Cloud Protector servers` : Servers to for wich to retrieve traffic and alert events.

### Vendor Log API Trendmicro visionone specific parameters

`Trendmicro visionone token` : Trendmicro visionone token.

### Vendor Log API Cisco Duo specific parameters

`Cisco Duo API hostname` : Cisco Duo API hostname.

`Cisco Duo API ikey` : Cisco Duo API integration key.

`Cisco Duo API skey` : Cisco Duo API secret key.

### Vendor Log API Sentinel One Mobile specific parameters

`Sentinel One Mobile API hostname` : Sentinel One Mobile API hostname.

`Sentinel One Mobile API ikey` : Sentinel One Mobile API integration key.

### Vendor Log API CSC DomainManager specific parameters

`CSC DomainManager API Key` : CSC DomainManager API Key.

`CSC DomainManager Authorization` : CSC DomainManager Authorization HTTP Header token prefixed by Bearer, ex: Bearer xxxx-xxxx-xxxx-xxxx.

### Vendor Log API Retarus specific parameters

`Retarus token` : Retarus token.

`Retarus channel` : Retarus channel.

### Vendor Log API Vectra specific parameters

`Vectra url` : Vectra url with scheme.

`Vectra secret key` : Vectra secret key.

`Vectra client id` : Vectra client id.

## Specific settings for Filebeat Listening Mode

### Filebeat Module

Fixme

### Filebeat Configuration

Fixme


