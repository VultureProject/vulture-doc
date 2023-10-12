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

`Size of the queue`: Maximum number of messages allowed in the action queue

---

`Size of batch dequeue`: Maximum number of logs to use in a batch operation

---

`Queue maximum workers`: Maximum number of workers to start for the action

---

`Queue timeout shutdown (ms)`: Number of milliseconds to wait before droping the remaining logs to process on the action (default 10 ms)

---

`Minimum messages to start a new worker`: Every time this number of logs is reached in the queue size, a new worker will be started (for example, if set to 1000: a new worker will be started at 1000 logs waiting in queue, then 2000, then 3000...) (default is queue size / maximum number of workers)

---

`Worker inactivity shutdown delay (ms)`: Number of milliseconds to wait before stopping a worker that didn't receive any log to process (default is 60000 ms = 1 min)

---

`Enable retry on failure`: Detect action failures and keep involved logs in the action queue to "replay" the action at a later time

---

`Enable disk queue on failure`: Use Disk-assisted Rsyslog queues to reliably keep logs on disk when accumulating in action queue (in case of action failures mostly).

    `Enable retry on failure` must be enabled

---

`High watermark target`: When the queue reaches this amount of waiting messages, the queue will begin to spool to disk.

    Only applies to disk-assisted queues, `Enable disk queue on failure` must be enabled

---

`Low watermark target`: When writing to disk is triggered by the `High watermark target`, it will return to in-memory queueing when the amount of logs in it falls back under this value.

    Only applies to disk-assisted queues, `Enable disk queue on failure` must be enabled

---

`Max file size of the queue in MB`: Maximum size of a single disk-assisted queue file, new files will be created to keep storing logs if previous ones become full.

    Only applies to disk-assisted queues, `Enable disk queue on failure` must be enabled

---

`Max disk space used by the queue in MB`: Total maximum size for all files storing logs on a disk-assisted queue. Note that the total size may slightly exceed that size as logs are always written completely to disk.

    Only applies to disk-assisted queues, `Enable disk queue on failure` must be enabled


## `File` parameters
*Work in progress*

## `RELP` parameters
*Work in progress*

## `Redis` parameters
*Work in progress*

## `Syslog` parameters
*Work in progress*

## `Elasticsearch/Opensearch` parameters
*Work in progress*

## `MongoDB` parameters
*Work in progress*

## `Kafka` parameters
This is a specific sectino to describe specific Kafka Log Forwarder configuration options.

`Broker`: A list representing the broker(s) to connect to. (example: *['1.2.3.4:9092]*)

---

`Topic`: The Kafka Topic to use when inserting new logs.


    When activating `Dynamic Topic`, the value in `Topic` will be processed as an [Rsyslog string template](https://www.rsyslog.com/doc/v8-stable/configuration/templates.html#string).

---

`Key`: The Kafka Key to use when inserting logs.

    When activating `Dynamic Key`, the value in `Key` will be processed as an [Rsyslog string template](https://www.rsyslog.com/doc/v8-stable/configuration/templates.html#string).

---

`Partition to which data is produced`: If set, will use this fixed partition number when inserting new values.

---

`Automatic partitioning`: If activated, will enable automatic handling of partitions with Kafka.

    Activating this feature will render `Partition to which data is produced` useless, as no manual partition scheming will be possible.

---

`Kafka parameters`: A dynamic list of key-value parameters directly provided to the [librdkafka library global configurations](https://github.com/confluentinc/librdkafka/blob/master/CONFIGURATION.md).

    The form will ensure basic key=value formatting, but user should ensure to always provide correct *key=value* format

---

`Kafka topic parameters`: A dynamic list of key-value parameters directly provided to the [librdkafka library topic configurations](https://github.com/confluentinc/librdkafka/blob/master/CONFIGURATION.md#topic-configuration-properties).

    The form will ensure basic key=value formatting, but user should ensure to always provide correct *key=value* format
