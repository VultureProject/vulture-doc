# Logs Forwarder

From this view, you'll be able to configure Log Forwarders.

The Log Forwarders will make it possible to redirect generated and/or received logs from specific Listeners to numerous destinations and technologies.

Those technologies are:

- **Internal files**
- **RELP protocol**
- **Redis**
- **Syslog protocol**
- **Elasticsearch/Opensearch**
- **MongoDB**
- **Kafka**
- **Sentinel**

For each type, you'll be able to configure both global and specific parameters.


## Global parameters

When creating a new Log Forwarder, you'll be able to configure the following global parameters:

`Enable forwarder`: Simply Enable of disable the forwarder, disabling it will remove it from any effective Listener configuration.

---

`Friendly name`: The front name of you Log Forwarder. Is simply used for ease-of-use and identification. It has to be unique, and any space will be replaced by a '_'.

---

`Send as raw`: This option specifies if the Forwarder should use the appropriate template for each associated Listener, or a generic template that will send the message without any modification.

    As stated, if the option is deactivated the output format will depend on each associated Listener: an HTTP Listener will have a format specific to Haproxy logs, a Log Listener will have a format depending on the types of received logs (defined through the `input logs type` parameter), etc...


### Advanced global parameters

By clicking the **Advanced** button on the lower right, the user will be able to further configure global (advanced) parameters for each Listener. Those options are better explained on [Rsyslog's documentation](https://www.rsyslog.com/doc/v8-stable/rainerscript/queue_parameters.html#queue-size)

`Size of the queue` (default: *10000*): Maximum number of messages allowed in the action queue

---

`Size of batch dequeue` (default: *300*): Maximum number of logs to use in a batch operation

---

`Queue maximum workers` (default: *1*): Maximum number of workers to start for the action

---

`Queue timeout shutdown (ms)` (default: [*10ms*](https://www.rsyslog.com/doc/rainerscript/queue_parameters.html#queue-timeoutworkerthreadshutdown)): Number of milliseconds to wait before droping the remaining logs to process on the action (default 10 ms)

---

`Minimum messages to start a new worker` (default: *Size of the queue / Queue maximum workers*): Every time this number of logs is reached in the queue size, a new worker will be started (for example, if set to 1000: a new worker will be started at 1000 logs waiting in queue, then 2000, then 3000...) (default is queue size / maximum number of workers)

---

`Worker inactivity shutdown delay (ms)` (default: *60000ms (60s)*): Number of milliseconds to wait before stopping a worker that didn't receive any log to process (default is 60000 ms = 1 min)

---

`Enable retry on failure` (default: *false*): Detect action failures and keep involved logs in the action queue to "replay" the action at a later time

---

`Enable disk queue on failure` (default: *false*): Use Disk-assisted Rsyslog queues to reliably keep logs on disk when accumulating in action queue (in case of action failures mostly).

    `Enable retry on failure` must be enabled

---

`High watermark target` (default: *8000*): When the queue reaches this amount of waiting messages, the queue will begin to spool to disk.

    Only applies to disk-assisted queues, `Enable disk queue on failure` must be enabled

---

`Low watermark target` (default: *6000*): When writing to disk is triggered by the `High watermark target`, it will return to in-memory queueing when the amount of logs in it falls back under this value.

    Only applies to disk-assisted queues, `Enable disk queue on failure` must be enabled

---

`Max file size of the queue in MiB` (default: *256MiB*): Maximum size of a single disk-assisted queue file, new files will be created to keep storing logs if previous ones become full.

    Only applies to disk-assisted queues, `Enable disk queue on failure` must be enabled

---

`Max disk space used by the queue in MiB` (default: *0MiB (unlimited)*): Total maximum size for all files storing logs on a disk-assisted queue. Note that the total size may slightly exceed that size as logs are always written completely to disk.

    Only applies to disk-assisted queues, `Enable disk queue on failure` must be enabled

---

`Folder to store queue files to` (default: */var/tmp*): Existing directory (**in the Rsyslog jail**) to write queue spool files to.

    Only applies to disk-assisted queues, `Enable disk queue on failure` must be enabled

!!! warning
    The folder should be created prior to defining it here, and should be available in the **Rsyslog jail**!


## `File` parameters
This is a section to describe specific File Log Forwarder configuration options.

`Local File path`: Path of the file to write in. Note that the file will be stored inside rsyslog jail (/zroot/rsyslog).

---

`Flush interval` (in seconds): Set the maximum delay to flush buffer to disk.

---

`Asynchronous writing`: Write logs asynchronously.

---

`File(s) retention time` (in days): Specify the time to keep rotated log files before deletion.

---

`Execute rotation every`: The rotation period can be configured here between every day, week, month or year.


## `RELP` parameters
This is a section to describe specific RELP Log Forwarder configuration options.

`Remote IP`: Set the IP address of the remote server.

---

`Remote TCP port`: Set the port of the remote server.

---

`Enable TLS encryption`: If set to on, the RELP connection will be encrypted using TLS (`Use TLS Certificate or CA` **MUST** be set when this parameter is *on*).

---

`Use TLS Certificate or CA`: X509Certificate object to verify server certificate.


## `Redis` parameters
This is a section to describe specific Redis Log Forwarder configuration options.

`Remote IP`: Set the IP address of the remote Redis server.

---

`Remote TCP port`: Set the port of the remote Redis server.

---

`Redis insertion mode`:

 - **Queue/list** mode: Insert logs on a [Redis list](https://redis.io/docs/data-types/lists/) using lpush/rpush commands
 - **Set/keys** mode: Insert logs in a specific [Redis key](https://redis.io/docs/manual/keyspace/) using set/setex commands
 - **Channel** mode: Insert logs on a specific [Redis channel](https://redis.io/docs/interact/pubsub/) using the publish command
 - **Stream** mode: Insert logs on a specific [Redis stream](https://redis.io/docs/data-types/streams/) using the xadd command

---

`Key`: The key, list, channel or stream used to insert logs in Redis.

---

`Dynamic key`: If activated, the key name will be dynamically generated from available Rsyslog variables.

---

`Password`: Provide the Redis server password to authenticate with (if unset, the Redis will be assumed to have no authentication).

---

`Use RPUSH`: Use RPUSH instead of LPUSH to insert a new log.

    This is only available for list insertion mode

---

`Expiration of the key (s)`: Use SETEX instead of SET to create keys with an expiration.

    This is only available for key insertion mode

---

`Stream field`: Set the stream's field to use to insert the log in (default to '*msg*').

    This is only available for stream insertion mode

---

`Maximum stream size`: [Cap the stream size](https://redis.io/docs/data-types/streams/#capped-streams) by approximately this number of entries. Oldest stream indexes will be flushed once the value is reached.

    This is only available for stream insertion mode


## `Syslog` parameters
This is a section to describe specific Syslog Log Forwarder configuration options.

`Remote IP`: IP address on which logs are sent to.

---

`Remote port`: Port on which logs are sent to.

---

`Protocol`: The IP protocol to use (either TCP and UDP).

---

`ZIP level`: [Compression level](https://www.rsyslog.com/doc/configuration/modules/omfwd.html#ziplevel) for messages (from 0 to 9).


## `Elasticsearch/Opensearch` parameters
This is a section to describe specific Elasticsearch Log Forwarder configuration options.

`Servers list`: Provide a list of servers to send logs to (example: *['1.2.3.4:9200']*, the value should be formatted as a list).

---

`Elasticsearch/OpenSearch 8 compatibility`: Tell Rsyslog to turn on [Elasticsearch/OpenSearch 8 compatibility(https://www.rsyslog.com/doc/configuration/modules/omelasticsearch.html#esversion-major)].

---

`Enable Elasticsearch datastreams support`: Option to allow log insertion into a compatible datastream.

---

`Handle retries on ELS insertion`: Let Rsyslog [handle ELS/OpenSearch specific log insertion failures](https://www.rsyslog.com/doc/configuration/modules/omelasticsearch.html#example-5) with more reliability.

---

`Index Pattern`: Specify an Elastic index where logs are sent (pattern is dynamic and can use [Rsyslog variables](https://www.rsyslog.com/doc/configuration/templates.html#string)).

---

`Username`: If necessary, set the username for authentication.

---

`Password`: If necessary, set the password for authentication.

---

`Use a TLS Profile`: TLS Profile to use when communicating with distant nodes.


## `MongoDB` parameters
This is a section to describe specific MongoDB Log Forwarder configuration options.

`MongoDB URI`: Uri of the reachable MongoDB target (example: *'mongodb://1.2.3.4:9091/?replicaset=Vulture&ssl=true'*).

---

`Database`: Set the database to use to store collections into.

---

`Collection`: The collection where logs will be inserted.

---

`Use TLS Certificate or CA`: X509Certificate object used to communicate with remote server.


## `Kafka` parameters
This is a section to describe specific Kafka Log Forwarder configuration options.

`Broker`: A list representing the broker(s) to connect to. (example: *['1.2.3.4:9092']*, the value should be formatted as a list).

---

`Topic`: The Kafka Topic to use when inserting new logs.


    When activating `Dynamic Topic`, the value in `Topic` will be processed as an [Rsyslog string template](https://www.rsyslog.com/doc/v8-stable/configuration/templates.html#string).

---

`Key`: The Kafka Key to use when inserting logs.

    When activating `Dynamic Key`, the value in `Key` will be processed as an [Rsyslog string template](https://www.rsyslog.com/doc/v8-stable/configuration/templates.html#string).

---

`Partition to which data is produced`: If set, will use this fixed partition number when inserting new entries.

---

`Automatic partitioning`: If activated, will enable automatic handling of partitions with Kafka.

    Activating this feature will render `Partition to which data is produced` useless, as no manual partition scheming will be possible.

---

`Kafka parameters`: A dynamic list of key-value parameters directly provided to the [librdkafka library global configurations](https://github.com/confluentinc/librdkafka/blob/master/CONFIGURATION.md).

    The form will ensure basic key=value formatting, but user should ensure to always provide correct *key=value* format

---

`Kafka topic parameters`: A dynamic list of key-value parameters directly provided to the [librdkafka library topic configurations](https://github.com/confluentinc/librdkafka/blob/master/CONFIGURATION.md#topic-configuration-properties).

    The form will ensure basic key=value formatting, but user should ensure to always provide correct *key=value* format


## `Sentinel` parameters
This is a section to describe specific Sentinel Log Forwarder configuration options.

`Tenant ID`: The ID of the tenant to use (will be used to generate the authentication URIs).

---

`Client ID`: The client ID for OpenID application authentication.

---

`Client Secret`: The client secret for OpenID application authentication.

---

`DCR`: The Sentinel **Data Collection Rule** to use while ingesting data.

---

`DCE`: The Sentinel Data **Collection Endpoint** to use for ingestion.

---

`Stream Name`: The Sentinel stream on which to insert the logs.

---

`Scope`: The OpenID scope to use. For [Sentinel ingestion API](https://docs.cribl.io/edge/destinations-sentinel/#auth), corresponds to the Azure Environment.

---

`Batch max size`: Sets the maximum amount of logs to add in a single batched request.

---

`Batch max bytes`: Sets the maximum size of messages (in bytes) for a single batched request.

---

`Compression level`: 

Activates and defines the level of compression of requests:

- ***balanced**: balance between speed and compression (default)
- ***0** : No compression*
- ***1** : Fastest compression*
- *...*
- ***9** : Best compression*

---

`Use a TLS Profile`: TLS Profile to use when communicating with distant nodes.

---

`Use Proxy`: Use a proxy to connect to the OMSentinel APIs

---

`Custom Proxy`: Custom proxy to use (will use system proxy if not set)