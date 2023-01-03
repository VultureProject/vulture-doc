# WebGUI - Menu "Services / Listener settings"

From this view you can edit the settings of a specific listener.

Multiple modes are available when creating a listener :

 - **LOG** : To collect logs with Rsyslog
 - **TCP** : Create a TCP HAProxy frontend
 - **HTTP** : Create an HTTP HAProxy frontend

Depending on which mode you chose, configuration parameters differ.

## Global parameters

Some of the following configuration parameters are not used in some specific cases, mentionned for each of them.

`Enabled` : You can here enable or disable your listener.

`Name` : Here you can specify a friendly name for your listener. You cannot have multiple listeners with the same name.

`Listeners` : This parameter is not used in LOG mode with listening mode Kafka, Redis or File.

Here you can configure the listening, by configuring for each row the following parameters :

- **Listen address** : Select the IP address you want to listen on
- **Port** : Configure the port you want to listen on
- **TLS Profile** : Not supported for now in LOG mode, here you can select a [TLS Profile](tls.md)
- **Allow from** : "Any" by default, configure a comma separated list of allowed IP addresses to connect from
- **Max src** : Configure a max number of source IP addresses allowed to connect
- **Max rate** : Configure a max rate

`Enable logging` : This parameter is implicitly enabled in LOG mode.

You can here enable or disable events forwarding. Mandatory if you want to select a [Log forwarder](/apps/logfwd/).

`Log forwarders` : This parameter is useless if you select a mode different of LOG and you disable logging.

You can here select Log forwarder(s).

If events are correctly parsed by Rsyslog, depending on which ruleset is configured.

`Log forwarders parse failure` : This parameter is useless if you select a mode different of LOG and you disable logging.

You can here select Log forwarder(s).

If events are not parsed by Rsyslog, depending on which ruleset is configured.

`Log condition (advanced)` : This parameter is useless if you select a mode different of LOG and you disable logging.

You can here configure an Rsyslog custom configuration bloc. Only use this parameter if you know what your doing.

`Tenants config` : This parameter is useless if you select a mode different of LOG and you disable logging.

Here you can select a [Multi-tenants configuration](tenant.md), that will be used to enrich logs and select enrichment databases.

`Enable reputation logging` : This parameter is useless if you select a mode different of LOG and you disable logging.

Here you can enable or disable logs enrichment with Rsyslog, by configuring parameters below.

`Reputation database IPv4` : This parameter is useless if you select a mode different of LOG and you disable logging.

Here you can select an [IPv4 MMDB database](reputation.md) to enrich logs with source and destination IPv4 addresses informations (ex: reputation).

`Reputation database IPv6` : This parameter is useless if you select a mode different of LOG and you disable logging.

Here you can select an [IPv6 MMDB database](reputation.md) to enrich logs with source and destination IPv6 addresses informations (ex: reputation).

`GeoIP database (IPv4)` : This parameter is useless if you select a mode different of LOG and you disable logging.

Here you can select an [GeoIP MMDB database](reputation.md) to enrich logs with public source and destination IP addresses localization.

`Reputation contexts` : This parameter is useless if you select a mode different of LOG and you disable logging.

Here you can configure more specificly the enrichment of logs by selecting and configuring 3 fields by row :

 - **Enabled** : Enable of disable the row
 - **IOC database** : Select the [reputation context](reputation.md) to use
 - **Input field name** : Configure the field name to send to database
 - **Destination field name** : Configure the field name you want to stock the result into


## LOG mode

Here is the list of LOG mode configuration parameters.

`Listening mode` : Here you chose a listening mode for your input :

 - **UDP** (listen logs with the Rsyslog imudp module)
 - **TCP** (listen logs with the Rsyslog imtcp module)
 - **TCP & UDP** (listen logs with Rsyslog imudp and imtcp module)
 - **RELP** (listen logs with Rsyslog imrelp module)
 - **FILE** (listen logs with Rsyslog imfile module)
 - **API CLIENT** (retrieve logs from external API events collect)
 - **KAFKA** (collect logs from a kafka server, with Rsyslog imkafka module)
 - **REDIS** (collect logs from a redis server, with Rsyslog imhiredis module)

Depending on which listening mode you chose, configuration settings differs.

`Ruleset (input logs type)` : Here you can select the format of input logs, for example :

 - **generic_json** (json formatted logs)
 - **raw_to_json** (no specific format, but convert logs to json)


### TCP listening mode specific parameters

`Disable Octet Counting Framing` : Here you specify the Rsyslog imtcp option "SupportOctetCountedFraming", this is an advanced option, enable the option only if you know what you are doing.

`Timeout connect` : Configure the allowed connect timeout (in ms) after which HAProxy will end new connection.

`Timeout client` : Set the maximum inactivity time on the client side.

### FILE listening mode specific parameters

`Node` : Configure the node on which you want to listen on file (or kafka or redis).

`File path` : Specify the absolute path of the file to listen on.

`Tags` : Specify one or multiple comma separated tag(s) to associate on your listener.

### KAFKA listening mode specific parameters

`Kafka Brokers` : Configure comma separated list of Kafka broker(s) to poll logs from.

`Kafka topic` : Configure kafka topic to poll logs from.

`Kafka consumer group` : Optional, configure the kafka consumer group to use to poll logs from.

### REDIS listening mode specific parameters

This listener relies on rsyslog / imhiredis, and has two modes of operation :

`Queue Mode, using push/pop` : The queue mode will LPOP or RPOP your message from a redis list.

Following parameters are required :

 - **Redis consumer mode** : Set mode to "queue" to enable the queue mode
 - **Redis key** : The key to xPOP on
 - **Redis server** : The name or IP address of the redis server (Vulture's Internal redis is 127.0.0.3)
 - **Redis port** : The redis listening port (default is 6379)

Following parameters are optional :

 - **Redis password** : If set, the plugin will issue an "AUTH" command before calling xPOP
 - **Use LPOP** : If set to "on", LPOP will be used instead of default RPOP

Redis pipelining is used inside the workerthread, with a hardcoded batch size of #10.

Imhiredis will query Redis every second to see if entries are in the list, if that's the case they will be dequeued continuously by batches of 10 until none remains.

Due to its balance between polling interval and pipelining and its use of lists, this mode is quite performant and reliable.
However, due to the 1 second polling frequency, one may consider using the `subscribe` mode instead if very low latency is required.

`Chanel Mode, using pub/sub` : The channel mode will SUBSCRIBE to a redis channel.

The "key" parameter is required and will be used for the subscribe channel.

Following parameters are required :

 - **Redis consumer mode** : Set mode to "subscribe" to enable the subscribe mode
 - **Redis key** : The key to subscribe to (aka the "channel")
 - **Redis server** : The name or IP address of the redis server
 - **Redis port** : The redis listening port

Following parameters are optional :

 - **password** : If set, the plugin will issue an "AUTH" command before listening to a channel
 - **uselpop** : Useless in channel mode


### API CLIENT listening mode specific parameters

`API Parser Type` : Here you can chose the technology of events you want to retrieve api events from.

The following endpoints are supported :

 - forcepoint
 - elasticsearch
 - symantec
 - aws_bucket
 - akamai
 - office_365
 - imperva
 - reachfive
 - mongodb
 - defender_atp
 - cortex_xdr
 - cybereason
 - cisco_meraki
 - proofpoint_tap

### API CLIENT Forcepoint specific parameters

`Forcepoint host` : Beginning url of the forcepoint endpoint to retrieve events from. Logs will be collected from {forcepoint_host}/siem/logs.

`Forcepoint username` : Username to use to authenticate to Forcepoint API.

`Forcepoint password` : Password to use to authenticate to Forcepoint API.

### API CLIENT Elaticsearch specific parameters

`Elasticsearch host` : Comma separated list of Elasticsearch host(s) to retrieve events from.

    Example : http://192.168.1.1:9200,http://192.168.1.2:9200

`Elasticsearch verify ssl` : Enable or disable the verification of Elasticsearch certificate.

`Elasticsearch auth` : Enable or disable authentication to Elasticsearch host(s).

`Elasticsearch username` : If "Elasticsearch auth" is enabled, username to use to authentication to Elasticsearch.

`Elasticsearch password` : If "Elasticsearch auth" is enabled, password to use to authentication to Elasticsearch.

`Elasticsearch index` : Elasticsearch index to retrieve logs from.

### API CLIENT Symantec specific parameters

`Symantec username` : Username to use to authenticate on Symantec API endpoint.

`Symantec password` : Password to use to authenticate on Symantec API endpoint.

### API CLIENT AWS bucket specific parameters

`AWS Access Key Id` : Key ID to use to authenticate on AWS API endpoint.

`AWS Secret Access Key` : Secret key to use to authenticate on AWS API endpoint.

`AWS Bucket Name` : Bucket name to retrieve events from.

### API CLIENT Akamai specific parameters

`Akamai Host` : Akamai domaine name to collect events from.

`Akamai Client Secret` : Client Secret to use to authenticate on Akamai API endpoint.

`Akamai Access Token` : Access Token to use to authenticate on Akamai API endpoint.

`Akamai Client Token` : Client Token to use to authenticate on Akamai API endpoint.

`Akamai Config ID` : Config ID to use to retrieve events from Akamai API endpoint.

### API CLIENT Office365 specific parameters

`Office365 Tenant ID` : Tenant to use to collect events from Office365 API endpoint.

`Office365 Client ID` : Client ID to use to authenticate on Akamai API endpoint.

`Office365 Client Secret` : Client secret to use to authenticate on Akamai API endpoint.

### API CLIENT Imperva specific parameters

`Imperva Base Url` : Base URL to use to collect events from. It should ends with a /.

`Imperva Api ID` : App ID to use to authenticate on Imperva API endpoint.

`Imperva Api Key` : Api secret to use to authenticate on Imperva API endpoint.

`Imperva Private Key` : Private Key to use to decrypt collected events from Imperva API endpoint.

### API CLIENT ReachFive specific parameters

`ReachFive Host` : Host name to use to retrieve events from. Ex: reachfive.domain.com.

`ReachFive Client ID` : Client ID to use to authenticate on ReachFive API endpoint.

`ReachFive Client Secret` : Client Secret to use to authenticate on ReachFive API endpoint.

### API CLIENT MongoDB (Atlas) specific parameters

`Mongodb API User` : User to use to authenticate on MongoDB API endpoint.

`MongoDB API Password` : Password to use to authenticate on MongoDB API endpoint.

`MongoDB API Group ID` : Group ID to use to retrieve events from MongoDB API endpoint.

### API CLIENT Defender ATP specific parameters

`MDATP API Tenant` : Tenant ID to use to retrieve events from Defender ATP API endpoint.

`MDATP API App ID` : App ID to use to authenticate on Defender ATP API endpoint.

`MDATP API Secret` : Secret to use to authenticate on Defender ATP API endpoint.

### API CLIENT Cortex XDR specific parameters

`Cortex XDR Host` : Host name to use to retrieve events from API endpoint.

    This parameter will be used as : https://api-{cortex_xdr_host}/public_api/v1/

`Cortex XDR API Key ID` : API Key ID to use to authenticate on API endpoint.

`Cortex XDR API Key` : API Key to use to authenticate on API endpoint.

### API CLIENT Cybereason specific parameters

`Cybereason Host` : Base URL (with scheme) to use to retrieve events from Cybereason API endpoint.

`Cybereason Username` : Username to use to authenticate on Cybereason API endpoint.

`Cybereason Password` : Password to use to authenticate on Cybereason API endpoint.

### API CLIENT Cisco Meraki specific parameters

`Cisco Meraki API Key` : API Key to use to authenticate on Cisco Meraki API endpoint.

### API CLIENT Proofpoint TAP specific parameters

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

