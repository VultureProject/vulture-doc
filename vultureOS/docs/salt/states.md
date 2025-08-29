# Examples of States

## Usefull commands

### On VultureOS

Without salt master:
```
salt-call state.apply --local
```

Apply a specific state:
```
salt-call state.apply vulture.frontend_present
```

Increase verbosity:
```
salt-call state.apply -ldebug
```

Test a state with a dry run:
```
salt-call state.apply test=True
```

### On salt master

```
salt "<appliance hostname>" cmd.run "salt-call state.apply"
```

```
salt --hide-timeout -t5 -C "G@roles:<group name>" cmd.run "cat /etc/resolv.conf"
```

## Configuration example

Be sure to specify required dependencies in the state.

For example, a workflow needs at least a frontend and a backend so in the workflow state, you have to delcare them in requirements
``` yaml
state_workflow_present:
  vulture.workflow_present:
    - require:
      - id: state_frontend_present
      - id: state_backend_present
```

### Whitelist

``` yaml
state_whitelist_salt_master:
  vulture.whitelist_salt_master:
    - name: "Salt Master IP"
    - ip_address: 10.0.2.1
```

### Node

``` yaml
state_node_present:
  vulture.node_present:
    - require:
      - id: state_forwarder_present
    - data:
      - name: "vulture"
        static_routes: |-
          static_routes="net1 net2 net3"
          route_net1="-net 192.168.0.0/24 192.168.0.1"
          route_net2="-net 192.168.1.0/24 192.168.1.1"
          route_net3="-net 192.168.2.0/24 192.168.2.1"
        pf_custom_param_config: "### Custom global parameters test"
        pf_custom_rdr_config: |-
          ### Custom RDR rules
          nat inet from 127.0.0.5 to any -> (vmx0)
        pstats_forwarders:
          - syslog_forwarder
```

### Network Interface

``` yaml
state_netif_present:
  vulture.netif_present:
    - data:
      - net_int_device:
        - dev: vtnet0
          node_name: vulture
```

### Network Address

``` yaml
state_network_address_present:
  vulture.network_address_present:
    - require:
      - id: state_netif_present
    - data:
      - name: System
        type: system
        ip: 10.0.2.2
        prefix_or_netmask: "255.255.255.0"
        net_int_device:
          - dev: vtnet0
            node_name: vulture
```

### TLS Profile

``` yaml
state_tlsprofile_present:
  vulture.tlsprofile_present:
    - data:
      - id: 2
        name: Custom TLS profile
        x509_certificate: vulture
        protocols:
          - tlsv11
          - tlsv12
          - tlsv13
        cipher_suite: "broad"
        alpn:
          - h2
          - http/1.1
        verify_client: "none"
        ca_cert: null
```

### Log Forwarder

``` yaml
state_forwarder_present:
  vulture.forwarder_present:
    - data:
      - forwarder_type: File
        name: file_forwarder
        file: /tmp/testing
        flush_interval: 2
      - forwarder_type: File
        name: file_forwarder_raw
        file: /tmp/raw
        flush_interval: 2
        send_as_raw: True
      - forwarder_type: RELP
        name: relp_forwarder
        target: 10.0.2.1
        port: 2323
        tls_enabled: True
      - forwarder_type: Redis
        name: redis_forwarder
        target: 127.0.0.5
        port: 6379
        key: "%$!techno%-%$!product%"
        dynamic_key: true
      - forwarder_type: Syslog
        name: syslog_forwarder
        target: 10.0.2.1
        port: 2424
        protocol: tcp
        zip_level: 4
      - forwarder_type: Elasticsearch
        name: ELS_forwarder
        servers: '["http://10.0.2.1:9200"]'
        es8_compatibility: True
        data_stream_mode: True
        index_pattern: "vulture-%$!timestamp:1:10%"
        enable_retry: True
        enable_disk_assist: True
      - forwarder_type: MongoDB
        name: mongodb_forwarder
        uristr: "mongodb://10.0.2.10:9091/?replicaset=Vulture&ssl=true"
        db: vulture
        collection: logs_mongodb_forwarder
      - forwarder_type: Kafka
        name: kafka_forwarder
        broker: '["10.0.2.1:9092"]'
        topic: logs
        dynaTopic: False
        key: "%$!techno%-%$!product%"
        dynaKey: True
        topicConfParam:
          - test="is a string"
          - test2=ok
        confParam:
          - a=b
          - c=d
          - e=f=gchoices.OPENIDChoices.JWT_SIGNATURE_TYPE[0]
        partitions_auto: True
      - forwarder_type: Sentinel
        name: sentinel_forwarder
        tenant_id: "47673b71-c5ae-4a2a-8d8a-e86e79f1f967"
        client_id: "47673b71-c5ae-4a2a-8d8a-e86e79f1f967"
        client_secret: "s3Cr3t"
        dcr: "dcr-cbb3586665ebdbc6ebadd796e3ba5bcf"
        dce: "example-a1b2.westus-1.ingest.monitor.azure.com"
        stream_name: "stream_CL"
        scope: "https://monitor.azure.com/.default"
        batch_maxsize:  10
        batch_maxbytes: 10485760
        compression_level: 5
        use_proxy: True
        custom_proxy: "http://1.2.3.4:1337"
```

### Error Templates

``` yaml
state_error_template_present:
  vulture.error_template_present:
    - data:
      - name: Test_Error_Template
        error_400_mode: display
        error_400_html: "HTTP/1.1 400 Bad Request\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\r\n<html><body><h1>400 Bad requesting</h1>\r\n<p>Your browser sent an invalid request.</p>\r\n</body></html>"
        error_400_url: "http://www.example.com/test/"
        error_403_mode: display
        error_403_html: "HTTP/1.1 403 Forbidden\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\r\n<html><body><h1>403 Forbidden</h1>\r\n<p>You don't have permission to access this url on this server.<br/></p>\r\n</body></html>"
        error_403_url: "http://www.example.com/test/"
        error_405_mode: display
        error_405_html: "HTTP/1.1 405 Method Not Allowed\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\r\n<html><body><h1>405 Method Not Allowed</h1>\r\n<p>The requested method is not allowed for that URL.</p>\r\n</body></html>"
        error_405_url: "http://www.example.com/test/"
        error_408_mode: display
        error_408_html: "HTTP/1.1 408 Request Timeout\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\r\n<html><body><h1>408 Request Timeout</h1>\r\n<p>Server timeout waiting for the HTTP request from the client.</p>\r\n</body></html>"
        error_408_url: "http://www.example.com/test/"
        error_425_mode: display
        error_425_html: "HTTP/1.1 425 Too Early\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\r\n<html><body><h1>425 Too Early</h1>\r\n<p>.</p>\r\n</body></html>"
        error_425_url: "http://www.example.com/test/"
        error_429_mode: display
        error_429_html: "HTTP/1.1 429 Too Many Requests\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\r\n<html><body><h1>429 Too Many Requests</h1>\r\n<p>The user has sent too many requests in a given amount of time.</p>\r\n</body></html>"
        error_429_url: "http://www.example.com/test/"
        error_500_mode: display
        error_500_html: "HTTP/1.1 500 Internal Server ErrTest_Error_Templateor\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\r\n<html><body><h1>500 Internal Server Error</h1>\r\n<p>The server encountered an internal error or\r\nmisconfiguration and was unable to complete\r\nyour request.</p>\r\n<p>Please contact the server administrator\r\nto inform them of the time this error occurred\r\nand the actions you performed just before this error.</p>\r\n<p>More information about this error may be available\r\nin the server error log.</p>\r\n</body></html>"
        error_500_url: "http://www.example.com/test/"
        error_502_mode: display
        error_502_html: "HTTP/1.1 502 Bad Gateway\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\r\n<html><body><h1>502 Bad Gateway</h1>\r\n<p>The proxy server received an invalid response from an upstream server.<br/></p>\r\n</body></html>"
        error_502_url: "http://www.example.com/test/"
        error_503_mode: display
        error_503_html: "HTTP/1.1 503 Service Unavailable\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\r\n<html><body><h1>503 Service Unavailable</h1>\r\n<p>The server is temporarily unable to service your\r\nrequest due to maintenance downtime or capacity\r\nproblems. Please try again later.</p>\r\n</body></html>"
        error_503_url: "http://www.example.com/test/"
        error_504_mode: display
        error_504_html: "HTTP/1.1 504 Gateway Timeout\r\nContent-type: text/html\r\nConnection: close\r\n\r\n\r\n<html><body><h1>504 Gateway Timeout</h1>\r\n<p>The gateway did not receive a timely response\r\nfrom the upstream server or application.</p>\r\n</body></html>"
        error_504_url: "http://www.example.com/test/"
```

### Frontend and listener

``` yaml
state_frontend_present:
  vulture.frontend_present:
    - require:
      - id: state_network_address_present
      - id: state_tlsprofile_present
      - id: state_error_template_present
    - data:
      - name: HTTPS
        mode: http
        https_redirect: true
        listeners:
          - interface_name: System
            ip: 10.0.2.10
            port: 443
            tls_profiles:
              - Custom TLS profile
          - interface_name: System
            ip: 10.0.2.10
            port: 80
        enable_logging_reputation: false
        enable_logging: true
        error_template: Test_Error_Template
        log_forwarders:
          - redis_forwarder
        log_condition: |
          {%raw%}{{redis_forwarder}}{%endraw%}
      - name: Frontend ssh
        mode: tcp
        listeners:
          - interface_name: System
            ip: 10.0.2.10
            port: 2222
        enable_logging_reputation: false
        enable_logging: false
      - name: Filebeat example
        mode: filebeat
        filebeat_listening_mode: api
        node: vulture
        redis_password: test
        listeners:
          - interface_name: System
            ip: 10.0.2.10
            port: 4444
        enable_logging_reputation: false
        enable_logging: true
        log_forwarders:
          - file_forwarder
        log_condition: |
          {%raw%}{{file_forwarder}}{%endraw%}
        filebeat_module: "f5"
        filebeat_config: |
          - module: f5
            bigipapm:
              enabled: true
              var.input: tcp
              var.syslog_host: %ip%
              var.syslog_port: %port%
        api_parser_use_proxy: true
        api_parser_custom_proxy: "http://10.0.2.1:3128"
        ruleset: "generic_json"
      - name: Redis Input json
        mode: log
        listening_mode: redis
        node: vulture
        ruleset: "generic_json"
        redis_server: 127.0.0.5
        redis_port: 6379
        redis_password: test
        redis_mode: queue
        redis_key: redis_input
        nb_workers: 2
        redis_batch_size: 100
        mmdb_cache_size: 10000
        enable_logging: true
        enable_logging_geoip: True
        logging_geoip_database: "Geolite2 Country"
        log_forwarders:
          - file_forwarder
          - redis_forwarder
        log_condition: |
          {%raw%}{{file_forwarder}}
          {{redis_forwarder}}{%endraw%}
      - name: Syslog input
        mode: log
        listening_mode: tcp
        ruleset: "raw_to_json"
        custom_tl_frame_delimiter: 200
        queue_type: linkedlist
        queue_size: 50000
        nb_workers: 4
        new_worker_minimum_messages: 10000
        light_delay_mark: 90
        full_delay_mark: 97
        shutdown_timeout: 5000
        enable_disk_assist: true
        save_on_shutdown: true
        high_watermark: 80
        low_watermark: 60
        max_file_size: 256
        max_disk_space: 1024
        spool_directory: /var/tmp
        listeners:
          - interface_name: System
            ip: 10.0.2.10
            port: 7841
        enable_logging: true
        enable_logging_geoip: True
        logging_geoip_database: "Geolite2 City"
        log_forwarders:
          - file_forwarder_raw
          - mongodb_forwarder
          - sentinel_forwarder
          - kafka_forwarder
          - ELS_forwarder
        log_forwarders_parse_failure:
          - file_forwarder_raw
        log_condition: |
          {%raw%}{{file_forwarder_raw}}
          {{mongodb_forwarder}}
          {{sentinel_forwarder}}
          {{kafka_forwarder}}
          {{ELS_forwarder}}{%endraw%}
```

### Backend

``` yaml
state_backend_present:
  vulture.backend_present:
    - data:
      - name: app1
        mode: http
        timeout_server: 1000
        timeout_connect: 1000
        balancing_mode: roundrobin
        servers:
          - port: 8004
            target: app1.web.lan
            weight: 1
            mode: net
        enable_http_health_check: True
        http_health_check_expect_match: rstatus
        http_health_check_expect_pattern: 302
      - name: app2
        mode: http
        timeout_server: 1000
        timeout_connect: 1000
        balancing_mode: roundrobin
        servers:
          - port: 8006
            target: app2.web.lan
            weight: 1
            mode: net
      - name: app3
        mode: http
        timeout_server: 1000
        timeout_connect: 1000
        balancing_mode: roundrobin
        servers:
          - port: 8008
            target: app31.web.lan
            weight: 1
            mode: net
          - port: 8008
            target: app32.web.lan
            weight: 1
            mode: net
      - name: custom
        mode: http
        timeout_server: 1000
        timeout_connect: 1000
        balancing_mode: roundrobin
        servers:
          - port: 80
            target: 10.0.2.1
            weight: 1
            mode: net
        enable_http_health_check: True
        http_health_check_expect_match: rstatus
        http_health_check_expect_pattern: 200
      - name: ssh
        mode: tcp
        timeout_server: 1000
        timeout_connect: 1000
        balancing_mode: roundrobin
        servers:
          - port: 22
            target: 10.0.2.1
            weight: 1
            mode: net
        enable_tcp_health_check: True
        tcp_health_check_expect_match: rstring
        tcp_health_check_expect_pattern: ^SSH.\*OpenSSH.\*
        tcp_health_check_interval: 10
```

### LDAP repository

``` yaml
state_ldaprepository_present:
  vulture.ldaprepository_present:
    - data:
      - name: LDAP_Main
        host: 10.0.2.1
        port: 6389
        protocol: 3
        encryption_scheme: none
        connection_dn: cn=admin,dc=web,dc=lan
        dn_password: admin
        base_dn: dc=web,dc=lan
        user_scope: 2
        user_dn: ou=users
        user_attr: uid
        user_objectclasses:
          - top
          - inetOrgPerson
          - customAuxiliaryClass
        group_objectclasses:
          - top
          - groupOfNames
          - extensibleObject
        user_groups_attr: memberOf
        user_filter: (objectClass=inetOrgPerson)
        user_account_locked_attr: ""
        user_change_password_attr: ""
        user_mobile_attr: mobile
        user_email_attr: mail
        group_scope: 2
        group_dn: ou=Policy
        group_attr: cn
        group_filter: (objectClass=groupOfNames)
        group_member_attr: member
        custom_attributes:
          - ldap_attribute: CustomAttr1
            output_attribute: my_attr_1
          - ldap_attribute: CustomAttr2
            output_attribute: my_attr_2
```

### User Scope

``` yaml
state_userscope_present:
  vulture.userscope_present:
    - data:
      - name: Gitlab Scopes
        repo_attributes:
          - condition_var_kind: always
            assignator: "="
            action_var_name: user_type
            action_var_kind: constant
            action_var: "user"
          - condition_var_kind: claim
            condition_var_name: groups
            condition_criterion: exists
            condition_match: ""
            assignator: +=
            action_var_name: claim_list
            action_var_kind: claim
            action_var: claim_list
          - condition_var_kind: claim
            condition_var_name: email
            condition_criterion: exists
            condition_match: ""
            assignator: "="
            action_var_name: mail
            action_var_kind: claim
            action_var: email
          - condition_var_kind: claim
            condition_var_name: mobile
            condition_criterion: exists
            assignator: "="
            action_var_name: mobile
            action_var_kind: claim
            action_var: mobile
          - condition_var_kind: claim
            condition_var_name: iss
            condition_criterion: exists
            assignator: "="
            action_var_name: iss
            action_var_kind: claim
            action_var: iss
```

### IDP

``` yaml
state_gitlab_connector_present:
  vulture.openid_present:
    - require:
      - state_userscope_present
    - data:
      - name: Gitlab
        provider: gitlab
        provider_url: https://gitlab.com
        client_id: <client_id>
        client_secret: <client_secret>
        scopes:
          - openid
          - read_user
          - profile
          - email
        use_proxy: false
        verify_certificate: true
        user_scope: Gitlab Scopes
        enable_jwt: True
        jwt_signature_type: RS256
        jwt_key: |
          -----BEGIN CERTIFICATE-----
          <certificate>
          -----END CERTIFICATE-----
```

### OTP

``` yaml
state_otp_present:
  vulture.otp_present:
    - data:
      - name: "Default TOTP"
        otp_type: "totp"
        totp_label: "Double Authentication"
```

### User Portal

``` yaml
state_userportal_present:
  vulture.userportal_present:
    - require:
      - id: state_frontend_present
      - id: state_userscope_present
      - id: state_gitlab_connector_present
    - data:
      - name: PortalAppsGitlab
        repositories:
          - Gitlab
        auth_type: form
        auth_timeout: 3600
        enable_timeout_restart: true
        disconnect_url: "/disconnect"
        enable_disconnect_message: true
        enable_disconnect_portal: true
        enable_oauth: false
        enable_sso_forward: false
      - name: PortalAppsMixed
        repositories:
          - Gitlab
          - LDAP_Main
        auth_type: form
        auth_timeout: 3600
        enable_timeout_restart: true
        disconnect_url: "/disconnect"
        enable_disconnect_message: true
        enable_disconnect_portal: true
        enable_oauth: false
        enable_sso_forward: false
      - name: PortalCustom
        enable_external: false
        repositories:
          - LDAP_Main
        auth_type: form
        oauth_timeout: 3600
        enable_timeout_restart: false
        disconnect_url: "/disconnect"
        enable_disconnect_message: true
        enable_disconnect_portal: true
        enable_registration: false
        enable_sso_forward: false
```

### ACL

``` yaml
state_acl_present:
  vulture.acl_present:
    - data:
      - name: "Internal_IP_source"
        enabled: true
        or_lines:
          - lines:
            - criterion: "src"
              converter: "ip"
              dns: false
              case: false
              pattern: "10.0.2.0/24"
```

### Workflow

``` yaml
state_workflow_present:
  vulture.workflow_present:
    - require:
      - id: state_frontend_present
      - id: state_backend_present
      - id: state_userportal_present
      - id: state_acl_present
    - data:
      - name: app1
        frontend: HTTPS
        authentication: PortalAppsGitlab
        backend: app1
        fqdn: app1.web.lan
        public_dir: /
      - name: app2
        frontend: HTTPS
        authentication: PortalAppsGitlab
        backend: app2
        fqdn: app2.web.lan
        public_dir: /myapp/
        enable_cors_policy: true
        cors_allowed_methods:
          - "GET"
          - "POST"
          - "OPTIONS"
        cors_allowed_origins: "*"
        cors_allowed_headers: "*"
        cors_max_age: 3600
      - name: lb_app
        frontend: HTTPS
        authentication: PortalAppsGitlab
        backend: app3
        fqdn: app3.web.lan
        public_dir: /
        acl_frontend:
          - name: Internal_IP_source
            action_satisfy: 200
            action_not_satisfy: 403
      - name: admin_app
        frontend: HTTPS
        authentication: PortalAppsMixed
        backend: custom
        fqdn: admin.web.lan
        public_dir: /
        acl_frontend:
          - name: Internal_IP_source
            action_satisfy: 200
            action_not_satisfy: 403
      - name: Internal ssh
        frontend: Frontend ssh
        backend: ssh
```
