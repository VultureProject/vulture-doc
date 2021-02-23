# Services / Listener settings

From this view you can edit the settings of a specific listener.

Multiple modes are available when creating a listener :
 - LOG (collect logs with Rsyslog)
 - TCP (create a TCP HAProxy frontend)
 - HTTP (create an HTTP HAProxy frontend)
 - IMPCAP (create an Rsyslog Impcap listener)


## LOG mode

Here is the list of available settings in LOG mode.

#### Enabled

You can here enable or disable your listener.

#### Name

Here you can specify a friendly name for your listener. You cannot have multiple listeners with the same name.

#### Listening mode

Here you chose a listening mode for your input :
 - UDP (listen logs with the Rsyslog imudp module)
 - TCP (listen logs with the Rsyslog imtcp module)
 - TCP & UDP (listen logs with Rsyslog imudp and imtcp module)
 - RELP (listen logs with Rsyslog imrelp module)
 - FILE (listen logs with Rsyslog imfile module)
 - API CLIENT (retrieve logs from external API events collect)
 - KAFKA (collect logs from a kafka server, with Rsyslog imkafka module)

Depending on which listening mode you chose, configuration settings differs.

### TCP listening mode specific parameters

#### Disable Octet Counting Framing

Here you specify the Rsyslog imtcp option "SupportOctetCountedFraming", this is an advanced option, enable the option only if you know what you are doing.

### FILE listening mode specific parameters

#### Node

Configure the node on which you want to listen on file.

#### File path

Specify the absolute path of the file to listen on.

#### Tags

Specify one or multiple comma separated tag(s) to associate on your listener.

### API CLIENT listening mode specific parameters

#### API Parser Type

Here you can chose the technology of events you want to retrieve api events from. For now, only following endpoints are supported :
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

#### Forcepoint host

Beginning url of the forcepoint endpoint to retrieve events from.
Logs will be collected from {forcepoint_host}/siem/logs.

#### Forcepoint username

Username to use to authenticate to Forcepoint API.

#### Forcepoint password

Password to use to authenticate to Forcepoint API.

### API CLIENT Elaticsearch specific parameters

#### Elasticsearch host

Comma separated list of Elasticsearch host(s) to retrieve events from.
Example : http://192.168.1.1:9200,http://192.168.1.2:9200

#### Elasticsearch verify ssl

Enable or disable the verification of Elasticsearch certificate.

#### Elasticsearch auth

Enable or disable the verification of Elasticsearch certificate.



#### Ruleset (input logs type)

Here you can select the format of listening logs, for example :
 - generic_json (json formatted logs)
 - raw_to_json (no specific format, but convert logs to json)
