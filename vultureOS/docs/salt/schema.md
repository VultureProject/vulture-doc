# Schema overview

## Config fields

``` yaml
configure_cluster:
    pf_ssh_restrict: Optional[str]
    pf_admin_restrict: Optional[str]
    cluster_api_key: Optional[str]
    oauth2_header_name: Optional[str]
    portal_cookie_name: Optional[str]
    public_token: Optional[str]
    ldap_repository: Union[int, None]
    redis_password: Optional[str]
    branch: Optional[str]
    smtp_server: Optional[str]
    pf_whitelist: Optional[str]
    pf_blacklist: Optional[str]
    ssh_authorized_key: Optional[str]
    rsa_encryption_key: Optional[str]
    logs_ttl: Optional[int]
    internal_tenants: Optional[int]
```

## Network Address fields

``` yaml
network_address_present:
    name: str
    type: str
    nic: List[str]
    ip: Optional[str]
    prefix_or_netmask: Optional[str]
    carp_vhid: int
    vlan: Optional[int]
    fib: Optional[int]
    lagg_proto: str in ("failover", "lacp", "loadbalance", "roundrobin", "broadcast", "none")
```

## Header fields

``` yaml
header_present:
    enabled: bool
    type: str in ('request', 'response')
    action: str in ('add-header', 'set-header', 'del-header', 'replace-header', 'replace-value')
    header_name: str in ("Accept", "Accept-Charset", "Accept-Encoding", "Accept-Language", "Accept-Datetime", "Authorization", "Cache-Control", "Connection", "Cookie", "Content-Length", "Content-MD5", "Content-Type", "Date", "DNT", "Expect", "From", "Front-End-Https", "Host", "If-Match", "If-Modified-Since", "If-None-Match", "If-Range", "If-Unmodified-Since", "Max-Forwards", "Origin", "Pragma", "Proxy-Authorization", "Proxy-Connection", "Range", "Referer", "TE", "User-Agent", "Upgrade", "Via", "Warning", "X-Requested-With", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection", "X-Http-Method-Override", "X-ATT-DeviceId", "X-Wap-Profile")
    match: str
    replace: str
    condition_action: str in ('', 'if', 'unless')
    condition: str
```

## Frontend fields

``` yaml
frontend_present:
    enabled: bool
    name: str
    tags: list
    mode: str in ('tcp', 'http', 'log', 'filebeat', 'impcap')
    listeners: list
    timeout_client: int
    timeout_keep_alive: int
    https_redirect: bool
    enable_logging: bool
    tenants_config: int
    enable_logging_reputation: bool
    logging_reputation_database_v4: Optional[int]
    logging_reputation_database_v6: Optional[int]
    enable_logging_geoip: bool
    logging_geoip_database: Optional[int]
    log_level: str in ('info', 'debug')
    log_forwarders: List[Any]
    log_forwarders_parse_failure: List[Any]
    log_condition: str
    keep_source_fields: dict
    ruleset: str
    parser_tag: Optional[str]
    listening_mode: str in ('udp', 'tcp', 'tcp,udp', 'relp', 'file', 'api', 'kafka', 'redis')
    filebeat_listening_mode: str in ("tcp", "udp", "file", "api")
    filebeat_module: str
    filebeat_config: str
    disable_octet_counting_framing: bool
    custom_tl_frame_delimiter: int
    headers: List[Header]
    custom_haproxy_conf: str
    enable_cache: bool
    cache_total_max_size: int
    cache_max_age: int
    enable_compression: bool
    compression_algos: List[str] in ('identity', 'gzip', 'deflate', 'raw-deflate')
    compression_mime_types: str
    error_template: Optional[int]
    reputation_contexts: list
    file_path: str
    kafka_brokers: list
    kafka_topic: str
    kafka_consumer_group: str
    redis_mode: str in ('queue', 'subscribe', 'stream')
    redis_server: str
    redis_port: int
    redis_key: str
    redis_password: str
    redis_use_lpop: bool
    redis_stream_consumerGroup: str
    redis_stream_consumerName: str
    redis_stream_startID: str in ('$', '-', '>') # New entries, All entries, Undelivered entries
    redis_stream_acknowledge: bool
    redis_stream_reclaim_timeout: NonNegativeInt
    nb_workers: int
    mmdb_cache_size: int
    redis_batch_size: int
    node: Optional[str]
    ratelimit_burst: Optional[int]
    ratelimit_interval: Optional[int]
    api_parser_type: str
    api_parser_use_proxy: bool
    api_parser_custom_proxy: Optional[str]
    api_parser_verify_ssl: bool
    api_parser_custom_certificate: Optional[dict]
```
<details>
  <summary>API Collector specific fields</summary>
```
    forcepoint_host: str
    forcepoint_username: str
    forcepoint_password: str
    symantec_username: str
    symantec_password: str
    symantec_token: str
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_bucket_name: str
    akamai_host: str
    akamai_client_secret: str
    akamai_access_token: str
    akamai_client_token: str
    akamai_config_id: str
    office365_tenant_id: str
    office365_client_id: str
    office365_client_secret: str
    imperva_base_url: str
    imperva_api_id: str
    imperva_api_key: str
    imperva_private_key: str
    imperva_last_log_file: str
    reachfive_host: str
    reachfive_client_id: str
    reachfive_client_secret: str
    mongodb_api_user: str
    mongodb_api_password: str
    mongodb_api_group_id: str
    mdatp_api_tenant: str
    mdatp_api_appid: str
    mdatp_api_secret: str
    cortex_xdr_host: str
    cortex_xdr_apikey_id: str
    cortex_xdr_apikey: str
    cortex_xdr_alerts_timestamp: Optional[datetime]
    cortex_xdr_incidents_timestamp: Optional[datetime]
    cybereason_host: str
    cybereason_username: str
    cybereason_password: str
    cisco_meraki_apikey: str
    cisco_meraki_timestamp: dict
    proofpoint_tap_host: str
    proofpoint_tap_endpoint: str
    proofpoint_tap_principal: str
    proofpoint_tap_secret: str
    sentinel_one_host: str
    sentinel_one_apikey: str
    sentinel_one_account_type: str in ('console', 'user service')
    carbon_black_host: str
    carbon_black_orgkey: str
    carbon_black_apikey: str
    netskope_host: str
    netskope_apikey: str
    blackberry_cylance_app_id: str
    blackberry_cylance_app_secret: str
    blackberry_cylance_host: str
    blackberry_cylance_tenant: str
    crowdstrike_client: str
    crowdstrike_client_id: str
    crowdstrike_client_secret: str
    crowdstrike_host: str
    defender_client_id: str
    defender_client_secret: str
    defender_token_endpoint: str
    gsuite_alertcenter_admin_mail: str
    gsuite_alertcenter_json_conf: str
    harfanglab_apikey: str
    harfanglab_host: str
    ms_sentinel_appid: str
    ms_sentinel_appsecret: str
    ms_sentinel_resource_group: str
    ms_sentinel_subscription_id: str
    ms_sentinel_tenant_id: str
    ms_sentinel_workspace: str
    nozomi_probe_host: str
    nozomi_probe_login: str
    nozomi_probe_password: str
    proofpoint_pod_cluster_id: str
    proofpoint_pod_token: str
    proofpoint_pod_uri: str
    rapid7_idr_apikey: str
    rapid7_idr_host: str
    sophos_cloud_client_id: str
    sophos_cloud_client_secret: str
    sophos_cloud_tenant_id: str
    trendmicro_worryfree_access_token: str
    trendmicro_worryfree_secret_key: str
    trendmicro_worryfree_server_name: str
    trendmicro_worryfree_server_port: str
    safenet_tenant_code: str
    safenet_apikey: str
    vadesecure_host: str
    vadesecure_login: str
    vadesecure_password: str
    vadesecure_o365_access_token: str
    vadesecure_o365_client_id: str
    vadesecure_o365_client_secret: str
    vadesecure_o365_host: str
    vadesecure_o365_tenant: str
    vadesecure_o365_access_token_expiry: Optional[datetime]
    waf_cloudflare_apikey: str
    waf_cloudflare_zoneid: str
    proofpoint_casb_api_key: str
    proofpoint_casb_client_id: str
    proofpoint_casb_client_secret: str
    proofpoint_trap_host: str
    proofpoint_trap_apikey: str
    waf_cloud_protector_host: str
    waf_cloud_protector_api_key_pub: str
    waf_cloud_protector_api_key_priv: str
    waf_cloud_protector_provider: str
    waf_cloud_protector_tenant: str
    waf_cloud_protector_servers: str
    trendmicro_visionone_token: str
    cisco_duo_host: str
    cisco_duo_ikey: str
    cisco_duo_skey: str
    sentinel_one_mobile_host: str
    sentinel_one_mobile_apikey: str
    csc_domainmanager_apikey: str
    csc_domainmanager_authorization: str
    retarus_token: str
    retarus_channel: str
    vectra_host: str
    vectra_secret_key: str
    vectra_client_id: str
    apex_api_key: str
    apex_application_id: str
    apex_server_host: str
    signalsciences_ngwaf_email: str
    signalsciences_ngwaf_token: str
    signalsciences_ngwaf_corp_name: str
    signalsciences_ngwaf_site_name: str
    gatewatcher_alerts_host: str
    gatewatcher_alerts_api_key: str
    cisco_umbrella_client_id: str
    cisco_umbrella_secret_key: str
    waf_barracuda_token: str
    beyondtrust_pra_client_id: str
    beyondtrust_pra_secret: str
    beyondtrust_pra_host: str
```
</details>

## Tenant fields

``` yaml
tenant_present:
    name: str
    additional_config: dict
```

## Listener fields

``` yaml
listener_present:
    id: str
    network_address: str
    port: int
    tls_profiles: List[int]
    max_src: int
    max_rate: int
    whitelist_ips: str
    rsyslog_port: int
```

## Frontend Reputation Context fields

``` yaml
frontend_reputation_context_present:
    enabled: bool
    reputation_ctx: int
    arg_field: str
    dst_field: str
```

## Log Forwarder fields

### Base fields

``` yaml
forwarder_present:
    name: str
    internal: bool
    send_as_raw: bool
    queue_size: int
    dequeue_size: int
    queue_timeout_shutdown: Optional[PositiveInt]
    max_workers: Optional[PositiveInt]
    new_worker_minimum_messages: Optional[PositiveInt]
    worker_timeout_shutdown: Optional[PositiveInt]
    enable_retry: bool
    enable_disk_assist: bool
    high_watermark: int
    low_watermark: int
    max_file_size: int
    max_disk_space: int
```

### OmFile specific fields

``` yaml
    forwarder_type: File
    file: str
    flush_interval: int
    async_writing: bool
    enabled: bool
    retention_time: int
    rotation_period: str in ("daily", "weekly", "yearly")
```

## OmRelp specific fields

``` yaml
    forwarder_type: RELP
    target: str
    port: int
    enabled: bool
    tls_enabled: bool
    x509_certificate: Optional[int]
```

## OmHiredis specific fields

``` yaml
    forwarder_type: Redis
    target: str
    port: int
    mode: str in ("queue", "set", "publish", "stream")
    enabled: bool
    key: str
    dynamic_key: Optional[bool]
    pwd: Optional[str]
    use_rpush: Optional[bool]
    expire_key: Optional[NonNegativeInt]
    stream_outfield: Optional[str]
    stream_capacitylimit: Optional[NonNegativeInt]
```

## OmFwd specific fields

``` yaml
    forwarder_type: Syslog
    target: str
    port: int
    enabled: bool
    protocol: str in ("tcp", "udp")
    zip_level: int 0 to 9
```

## OmElasticsearch specific fields

``` yaml
    forwarder_type: Elasticsearch
    servers: str
    es8_compatibility: bool
    data_stream_mode: bool
    retry_on_els_failures: bool
    index_pattern: str
    uid: Optional[str]
    pwd: Optional[str]
    enabled: bool
    x509_certificate: Optional[int]
```

## OmMongoDB specific fields

``` yaml
    forwarder_type: MongoDB
    db: str
    collection: str
    uristr: str
    enabled: str
    x509_certificate: Optional[int]
```

## OmKafka specific fields

``` yaml
    forwarder_type: Kafka
    broker: str
    enabled: bool
    topic: str
    key: str
    dynaKey: Optional[bool]
    dynaTopic: Optional[bool]
    topicConfParam: list
    confParam: list
    partitions_useFixed: Optional[int]
    partitions_auto: Optional[bool]
```

## Reputation Context fields

``` yaml
reputation_context_present:
    name: str
    db_type: str in ("ipv4", "ipv6", "ipv4_netstet", "ipv6_netset", "domain", "GeoIP")
    method: str in ("GET", "POST")
    url: str
    verify_cert: bool
    post_data: str
    custom_headers: dict
    auth_type: str in ("", "basic", "digest")
    user: Union[str, None]
    password: Union[str, None]
    tags: list
    content: bytes
    filename: str
    description: str
    last_update: str
    nb_netset: str
    nb_unique: str
    internal: bool
```

## Backend fields

``` yaml
backend_present:
    enabled: bool
    name: str
    mode: str in ("tcp", "http")
    timeout_connect: int
    timeout_server: int
    headers: List[Header]
    custom_haproxy_conf: str
    enable_tcp_health_check: bool
    tcp_health_check_linger: bool
    tcp_health_check_send: str
    tcp_health_check_expect_match: str in ('', 'string', 'rstring', 'binary', 'rbinary', '! string', '! rstring', '! binary', '! rbinary')
    tcp_health_check_expect_pattern: str
    tcp_health_check_interval: int
    enable_tcp_keep_alive: bool
    tcp_keep_alive_timeout: int
    http_backend_dir: str
    accept_invalid_http_response: bool
    http_forwardfor_header: Optional[str]
    http_forwardfor_except: Optional[str]
    enable_http_health_check: bool
    http_health_check_linger: bool
    http_health_check_method: str in ("GET", "POST", "PUT", "PATCH", "DELETE")
    http_health_check_uri: str
    http_health_check_version: str in ('HTTP/1.0', 'HTTP/1.1', 'HTTP/2')
    http_health_check_headers: dict
    http_health_check_expect_match: str in ("status", "rstatus", "string", "! status", "! rstatus", "! string", "! rstring")
    http_health_check_expect_pattern: str
    http_health_check_interval: int
    enable_http_keep_alive: bool
    http_keep_alive_timeout: int
    balancing_mode: str in ("roundrobin", "static-rr", "leastconn", "first", "source", "uri", "url_param", "hdr", "rdp-cookie")
    balancing_param: str
    tags: list
    servers: list
```

## Server fields

``` yaml
server_present:
    target: str
    mode: str in ("net", "unix")
    port: int
    tls_profile: str
    weight: int
    source: str
```

## Access Control List fields

``` yaml
access_control_lines_present:
     lines: list
```

## Access Control Rule fields

``` yaml
access_control_rule_present:
    criterion: str in ("src", "base", "hdr", "shdr", "http_auth_group", "method", "path", "url", "urlp", "path", "cook", "scook", "rdp_cookie")
    criterion_name: str
    converter: str in ("beg", "dir", "dom", "end", "hex", "int", "ip", "len", "reg", "str", "sub", "found")
    dns: bool
    case: bool
    operator: str in ("eq", "ge", "gt", "le", "lt", "")
    pattern: str
```

## Access Control fields

``` yaml
acl_present:
    name: str
    enabled: bool
    or_lines: list
```

## Base Repository fields

``` yaml
base_repository_present:
    name: str
```

## OTP fields

``` yaml
otp_present:
    otp_type: str in ("phone", "email", "onetouch", "totp")
    otp_phone_service: str in ('authy')
    api_key: str
    otp_mail_service: str in ('vlt_mail_service')
    key_length: int
    totp_label: str
```

## LDAP Repository fields

``` yaml
ldaprepository_present:
    host: str
    port: int
    protocol: int
    encryption_scheme: str in ('none', 'ldaps', 'start-tls')
    connection_dn: str
    dn_password: str
    base_dn: str
    user_scope: int in (0, 1, 2)
    user_dn: str
    user_attr: str
    user_objectclasses: list
    user_filter: str
    user_account_locked_attr: str
    user_change_password_attr: str
    user_groups_attr: str
    user_mobile_attr: str
    user_email_attr: str
    group_scope: int in (0, 1, 2)
    group_dn: str
    group_attr: str
    group_objectclasses: list
    group_filter: str
    group_member_attr: str
    custom_attributes: List[LDAPCustomAttributeMapping]
```

## LDAP Custom Attribute Mapping fields

``` yaml
ldap_custom_attribute_mapping_present:
    ldap_attribute: str
    output_attribute: str
```

## Repo Attributes fields

``` yaml
repo_attributes_present:
    condition_var_kind: str in ('claim', 'repo', 'constant', 'always')
    condition_var_name: str
    condition_criterion: str in ('equals', 'not equals', 'exists', 'not exists', 'contains', 'not contains', 'startswith', 'endswith')
    assignator: str in ('=', '+=')
    condition_match: str
    action_var_name: str
    action_var_kind: str in ('constant', 'claim', 'repo', 'merge', 'claim_pref', 'repo_pref')
    action_var: str
```

## User scope fields

``` yaml
userscope_present:
    name: str
    repo_attributes: list
```

## User Portal fields

``` yaml
userportal_present:
    name: str
    enable_external: bool
    external_listener: Optional[str]
    external_fqdn: str
    enable_tracking: bool
    repositories: list
    auth_type: str in ('form', 'basic', 'kerberos')
    portal_template: Optional[str]
    lookup_ldap_repo: str
    lookup_ldap_attr: str
    lookup_claim_attr: str
    repo_attributes: list # Deprecated in vulture-gui 1.2.11
    user_scope: Optional[str] # Replaces potential repo_attributes
    auth_cookie_name: Optional[str]
    auth_timeout: int
    enable_timeout_restart: bool
    enable_captcha: bool
    otp_repository: Optional[str]
    otp_max_retry: int
    disconnect_url: str
    enable_disconnect_message: bool
    enable_disconnect_portal: bool
    enable_registration: bool
    group_registration: str
    update_group_registration: bool
    enable_oauth: bool
    oauth_client_id: str
    oauth_client_secret: str
    oauth_redirect_uris: list
    oauth_redirect_uris_external: list
    oauth_timeout: int
    enable_refresh: bool
    enable_rotation: bool
    max_nb_refresh: int
    enable_sso_forward: bool
    sso_forward_type: str in ('form', 'basic', 'kerberos')
    sso_forward_tls_proto: str in ('tlsv13', 'tlsv12', 'tlsv11', 'tlsv10')
    sso_forward_tls_check: bool
    sso_forward_tls_cert: Optional[str]
    sso_forward_direct_post: bool
    sso_forward_get_method: bool
    sso_forward_follow_redirect_before: bool
    sso_forward_follow_redirect: bool
    sso_forward_return_post: bool
    sso_forward_content_type: str in ('urlencoded', 'multipart', 'json')
    sso_forward_url: str
    sso_forward_user_agent: str
    sso_forward_content: str
    sso_forward_enable_capture: bool
    sso_forward_capture_content: str
    sso_forward_enable_replace: bool
    sso_forward_replace_pattern: str
    sso_forward_replace_content: str
    sso_forward_enable_additionnal: bool
    sso_forward_additionnal_url: str
    sso_keep_client_cookies: Optional[bool]
```

## OPENID fields

``` yaml
openid_present:
    name: str
    provider: str in ('google', 'azure', 'facebook', 'github', 'keycloak', 'gitlab', 'linkedin', 'azureAD', 'MazureAD', 'openid', 'gov', 'nextcloud', 'digitalocean', 'bitbucket', 'gitea', 'digital_pass')
    provider_url: str
    client_id: str
    client_secret: str
    scopes: list
    use_proxy: bool
    verify_certificate: bool
    user_scope: Optional[str]
    enable_jwt: bool
    jwt_signature_type: str in ('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512')
    jwt_key: str
    jwt_validate_audience: bool
```

## X509 Certificate fields

``` yaml
x509certificate_present:
    name: str
    serial: int
    status: str
    cert: str
    key: str
    chain: str
    csr: str
    crl: str
    is_ca: bool
    is_vulture_ca: bool
    is_external: bool
    crl_uri: str
    rev_date: str
```

## TLS Profile fields

``` yaml
tlsprofile_present:
    name: str
    x509_certificate: str
    protocols: List[str] in ("tlsv13", "tlsv12", "tlsv11", "tlsv10")
    cipher_suite: str in ('advanced', 'broad', 'widest', 'legacy', 'AES128-GCM-SHA256', 'AES128-SHA', 'AES128-SHA256', 'AES256-GCM-SHA384', 'AES256-SHA', 'AES256-SHA256', 'DHE-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES128-SHA', 'DHE-RSA-AES128-SHA256', 'DHE-RSA-AES256-GCM-SHA384', 'DHE-RSA-AES256-SHA', 'DHE-RSA-AES256-SHA256', 'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-SHA', 'ECDHE-RSA-AES128-SHA256', 'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-SHA', 'ECDHE-RSA-AES256-SHA384', 'TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256')
    alpn: List[str] in ("h2", "http/1.1", "http/1.0")
    verify_client: str in ("none", "optional", "required")
    ca_cert: Optional[str]
```

## Workflow ACL fields

``` yaml
worflow_acl_present:
    id: str
    action_satisfy: str
    action_not_satisfy: str
    redirect_url_satisfy: str
    redirect_url_not_satisfy: str
```

## Workflow fields

``` yaml
workflow_present:
    name: str
    enabled: bool
    frontend: str
    acl_frontend: List[WorkflowACL]
    acl_backend: List[WorkflowACL]
    authentication: Optional[str]
    fqdn: str
    public_dir: str
    backend: str
    enable_cors_policy: bool
    cors_allowed_methods: List[str] in ('*', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'CONNECT', 'OPTIONS', 'TRACE')
    cors_allowed_origins: str
    cors_allowed_headers: str
    cors_max_age: int
```

## OpenVPN fields

``` yaml
openvpn_present:
    node: str
    enabled: bool
    remote_server: str
    remote_port: int
    tls_profile: str
    proto: str
```

## Portal Template fields

``` yaml
portaltemplate_present:
    name: str
    css: str
    html_login: str
    html_learning: str
    html_logout: str
    html_self: str
    html_password: str
    html_otp: str
    html_message: str
    html_error: str
    html_registration: str
    html_error_XXX: str
    email_subject: str
    email_body: str
    email_from: str
    error_password_change_ok: str
    error_password_change_ko: str
    error_email_sent: str
    email_register_subject: str
    email_register_from: str
    email_register_body: str
    login_login_field: str
    login_password_field: str
    login_captcha_field: str
    login_submit_field: str
    learning_submit_field: str
    password_old_field: str
    password_new1_field: str
    password_new2_field: str
    password_email_field: str
    password_submit_field: str
    otp_key_field: str
    otp_submit_field: str
    otp_resend_field: str
    otp_onetouch_field: str
    register_captcha_field: str
    register_username_field: str
    register_phone_field: str
    register_password1_field: str
    register_password2_field: str
    register_email_field: str
    register_submit_field: str
```
**Note :** XXX could be: 404, 405, 406, 500, 501, 502, 503 and 504

## Error Template fields

``` yaml
error_template_present:
    name: str
    error_XXX_mode: str in ('display','302','303')
    error_XXX_html: str
    error_XXX_url: str
```
**Note :** XXX could be: 400, 403, 405, 408, 425, 429, 500, 502, 503 and 504

## Ipsec fields

``` yaml
ipsec_present:
    node: str
    enabled: bool
    ipsec_type: str in ('tunnel')
    ipsec_keyexchange: str in ('ikev2')
    ipsec_authby: str in ('secret')
    ipsec_psk: str
    ipsec_fragmentation: bool
    ipsec_forceencaps: bool
    ipsec_ike: str
    ipsec_esp: str
    ipsec_dpdaction: str
    ipsec_dpddelay: str
    ipsec_rekey: bool
    ipsec_ikelifetime: str
    ipsec_keylife: str
    ipsec_right: str
    ipsec_leftsubnet: str
    ipsec_leftid: str
    ipsec_rightsubnet: str
```
