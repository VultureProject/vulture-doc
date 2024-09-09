# Schema overview

header_present:
    enabled: bool = True
    type: str in ('request', 'response')
    action: str in ('add-header', 'set-header', 'del-header', 'replace-header', 'replace-value')
    header_name: str in ("Accept", "Accept-Charset", "Accept-Encoding", "Accept-Language", "Accept-Datetime", "Authorization", "Cache-Control", "Connection", "Cookie", "Content-Length", "Content-MD5", "Content-Type", "Date", "DNT", "Expect", "From", "Front-End-Https", "Host", "If-Match", "If-Modified-Since", "If-None-Match", "If-Range", "If-Unmodified-Since", "Max-Forwards", "Origin", "Pragma", "Proxy-Authorization", "Proxy-Connection", "Range", "Referer", "TE", "User-Agent", "Upgrade", "Via", "Warning", "X-Requested-With", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Frame-Options", "X-Content-Type-Options", "X-XSS-Protection", "X-Http-Method-Override", "X-ATT-DeviceId", "X-Wap-Profile")
    match: str = "matching_regex"
    replace: str = "replacement pattern"
    condition_action: str in ('', 'if', 'unless')
    condition: str = ""


error_template_present:
    name: str
    error_XXX_mode: str in ('display','302','303')
    error_XXX_html: str
    error_XXX_url: str
**Note :** XXX could be: 400, 403, 405, 408, 425, 429, 500, 502, 503 and 504


frontend_present:
    enabled: bool = True
    name: str = "Listener"
    tags: list = []
    mode: str in ('tcp', 'http', 'log', 'filebeat', 'impcap')
    listeners: list
    timeout_client: int = 60
    timeout_keep_alive: int = 500
    https_redirect: bool = False
    enable_logging: bool = False
    tenants_config: int
    enable_logging_reputation: bool = False
    logging_reputation_database_v4: Optional[int]
    logging_reputation_database_v6: Optional[int]
    enable_logging_geoip: bool = False
    logging_geoip_database: Optional[int]
    log_level: str in ('info', 'debug')
    log_forwarders: List[Any] = []
    log_forwarders_parse_failure: List[Any] = []
    log_condition: str = ""
    keep_source_fields: dict = {}
    ruleset: str = "haproxy"
    parser_tag: Optional[str] = ""
    listening_mode: str in ('udp', 'tcp', 'tcp,udp', 'relp', 'file', 'api', 'kafka', 'redis')
    filebeat_listening_mode: str in ("tcp", "udp", "file", "api")
    filebeat_module: str = ""
    filebeat_config: str = ""
    disable_octet_counting_framing: bool = False
    custom_tl_frame_delimiter: int = -1
    headers: List[Header] = []
    custom_haproxy_conf: str = ""
    enable_cache: bool = False
    cache_total_max_size: int = 4
    cache_max_age: int = 60
    enable_compression: bool = False
    compression_algos: List[str] in ('identity', 'gzip', 'deflate', 'raw-deflate')
    compression_mime_types: str = "text/html,text/plain"
    error_template: Optional[int]
    reputation_contexts: list = []
    file_path: str = "/var/log/darwin/alerts.log"
    kafka_brokers: list = ["192.168.1.2:9092"]
    kafka_topic: str = "mytopic"
    kafka_consumer_group: str = "my_group"
    redis_mode: str in ('queue', 'subscribe', 'stream')
    redis_server: str = "127.0.0.5"
    redis_port: int = 6379
    redis_key: str = "vulture"
    redis_password: str = ""
    redis_use_lpop: bool = False
    redis_stream_consumerGroup: str = ""
    redis_stream_consumerName: str = ""
    redis_stream_startID: str in ('$', '-', '>') # New entries, All entries, Undelivered entries
    redis_stream_acknowledge: bool = True
    redis_stream_reclaim_timeout: NonNegativeInt = 0
    nb_workers: int = 8
    mmdb_cache_size: int = 0
    redis_batch_size: int = 10
    node: Optional[str]
    ratelimit_burst: Optional[int]
    ratelimit_interval: Optional[int]
    api_parser_type: str = ""
    api_parser_use_proxy: bool = False
    api_parser_custom_proxy: Optional[str]
    api_parser_verify_ssl: bool = True
    api_parser_custom_certificate: Optional[dict]
    forcepoint_host: str = ""
    forcepoint_username: str = ""
    forcepoint_password: str = ""
    symantec_username: str = ""
    symantec_password: str = ""
    symantec_token: str = "none"
    aws_access_key_id: str = ""
    aws_secret_access_key: str = ""
    aws_bucket_name: str = ""
    akamai_host: str = ""
    akamai_client_secret: str = ""
    akamai_access_token: str = ""
    akamai_client_token: str = ""
    akamai_config_id: str = ""
    office365_tenant_id: str = ""
    office365_client_id: str = ""
    office365_client_secret: str = ""
    imperva_base_url: str = ""
    imperva_api_id: str = ""
    imperva_api_key: str = ""
    imperva_private_key: str = ""
    imperva_last_log_file: str = ""
    reachfive_host: str = ""
    reachfive_client_id: str = ""
    reachfive_client_secret: str = ""
    mongodb_api_user: str = ""
    mongodb_api_password: str = ""
    mongodb_api_group_id: str = ""
    mdatp_api_tenant: str = ""
    mdatp_api_appid: str = ""
    mdatp_api_secret: str = ""
    cortex_xdr_host: str = ""
    cortex_xdr_apikey_id: str = ""
    cortex_xdr_apikey: str = ""
    cortex_xdr_alerts_timestamp: Optional[datetime]
    cortex_xdr_incidents_timestamp: Optional[datetime]
    cybereason_host: str = "domain.cybereason.net"
    cybereason_username: str = ""
    cybereason_password: str = ""
    cisco_meraki_apikey: str = ""
    cisco_meraki_timestamp: dict = {}
    proofpoint_tap_host: str = "https://tag-api-v2.proofpoint.com"
    proofpoint_tap_endpoint: str = "/all"
    proofpoint_tap_principal: str = ""
    proofpoint_tap_secret: str = ""
    sentinel_one_host: str = "srv.sentinelone.net"
    sentinel_one_apikey: str = ""
    sentinel_one_account_type: str in ('console', 'user service')
    carbon_black_host: str = "defense.conferdeploy.net"
    carbon_black_orgkey: str = ""
    carbon_black_apikey: str = ""
    netskope_host: str = "example.goskope.com"
    netskope_apikey: str = ""
    blackberry_cylance_app_id: str = ""
    blackberry_cylance_app_secret: str = ""
    blackberry_cylance_host: str = ""
    blackberry_cylance_tenant: str = ""
    crowdstrike_client: str = ""
    crowdstrike_client_id: str = ""
    crowdstrike_client_secret: str = ""
    crowdstrike_host: str = ""
    defender_client_id: str = ""
    defender_client_secret: str = ""
    defender_token_endpoint: str = ""
    gsuite_alertcenter_admin_mail: str = ""
    gsuite_alertcenter_json_conf: str = ""
    harfanglab_apikey: str = ""
    harfanglab_host: str = ""
    ms_sentinel_appid: str = ""
    ms_sentinel_appsecret: str = ""
    ms_sentinel_resource_group: str = ""
    ms_sentinel_subscription_id: str = ""
    ms_sentinel_tenant_id: str = ""
    ms_sentinel_workspace: str = ""
    nozomi_probe_host: str = ""
    nozomi_probe_login: str = ""
    nozomi_probe_password: str = ""
    proofpoint_pod_cluster_id: str = ""
    proofpoint_pod_token: str = ""
    proofpoint_pod_uri: str = "wss://logstream.proofpoint.com:443/v1/stream"
    rapid7_idr_apikey: str = ""
    rapid7_idr_host: str = "eu.api.insight.rapid7.com"
    sophos_cloud_client_id: str = ""
    sophos_cloud_client_secret: str = ""
    sophos_cloud_tenant_id: str = ""
    trendmicro_worryfree_access_token: str = ""
    trendmicro_worryfree_secret_key: str = ""
    trendmicro_worryfree_server_name: str = "cspi.trendmicro.com"
    trendmicro_worryfree_server_port: str = "443"
    safenet_tenant_code: str = ""
    safenet_apikey: str = ""
    vadesecure_host: str = ""
    vadesecure_login: str = ""
    vadesecure_password: str = ""
    vadesecure_o365_access_token: str = ""
    vadesecure_o365_client_id: str = ""
    vadesecure_o365_client_secret: str = ""
    vadesecure_o365_host: str = ""
    vadesecure_o365_tenant: str = ""
    vadesecure_o365_access_token_expiry: Optional[datetime]
    waf_cloudflare_apikey: str = ""
    waf_cloudflare_zoneid: str = ""
    proofpoint_casb_api_key: str = ""
    proofpoint_casb_client_id: str = ""
    proofpoint_casb_client_secret: str = ""
    proofpoint_trap_host: str = ""
    proofpoint_trap_apikey: str = ""
    waf_cloud_protector_host: str = "api-region.cloudprotector.com"
    waf_cloud_protector_api_key_pub: str = ""
    waf_cloud_protector_api_key_priv: str = ""
    waf_cloud_protector_provider: str = ""
    waf_cloud_protector_tenant: str = ""
    waf_cloud_protector_servers: str = ""
    trendmicro_visionone_token: str = ""
    cisco_duo_host: str = ""
    cisco_duo_ikey: str = ""
    cisco_duo_skey: str = ""
    sentinel_one_mobile_host: str = ""
    sentinel_one_mobile_apikey: str = ""
    csc_domainmanager_apikey: str = ""
    csc_domainmanager_authorization: str = ""
    retarus_token: str = ""
    retarus_channel: str = ""
    vectra_host: str = ""
    vectra_secret_key: str = ""
    vectra_client_id: str = ""
    apex_api_key: str = ""
    apex_application_id: str = ""
    apex_server_host: str = ""


class NetworkAddress(BaseModel):
    name: str
    type: str in ("system", "alias", "vlan", "lagg")
    nic: List[str]
    ip: Optional[str]
    prefix_or_netmask: Optional[str]
    carp_vhid: int = 0
    vlan: Optional[int] = 0
    fib: Optional[int] = 0
    lagg_proto: str in ("failover", "lacp", "loadbalance", "roundrobin", "broadcast", "none")


class Tenants(BaseModel):
    name: str
    chameleon_apikey: Optional[str] = ''


class Config(BaseModel):
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


class Listener(BaseModel):
    id: str = ""
    network_address: str
    port: int
    tls_profiles: List[int] = []
    max_src: int = 100
    max_rate: int = 1000
    whitelist_ips: str = "any"
    rsyslog_port: int = 10000


class FrontendReputationContext(BaseModel):
    enabled: bool = True
    reputation_ctx: int
    arg_field: str = ""
    dst_field: str = ""


class LogOm(BaseModel):
    name: str
    internal: bool = False
    send_as_raw: bool = False
    queue_size: int = 10000
    dequeue_size: int = 300
    queue_timeout_shutdown: Optional[PositiveInt]
    max_workers: Optional[PositiveInt]
    new_worker_minimum_messages: Optional[PositiveInt]
    worker_timeout_shutdown: Optional[PositiveInt]
    enable_retry: bool = False
    enable_disk_assist: bool = False
    high_watermark: int = 8000
    low_watermark: int = 6000
    max_file_size: int = 256
    max_disk_space: int = 1024


class LogOmFile(LogOm):
    file: str
    flush_interval: int = 1
    async_writing: bool = True
    enabled: bool = True
    retention_time: int = 30
    rotation_period: str in ("daily", "weekly", "yearly")


class LogOmRelp(LogOm):
    target: str = "1.2.3.4"
    port: int = 514
    enabled: bool = True
    tls_enabled: bool = True
    x509_certificate: Optional[int]


class LogOmHiredis(LogOm):
    target: str = "1.2.3.4"
    port: int = 6379
    mode: str in ("queue", "set", "publish", "stream")
    enabled: bool = True
    key: str = "MyKey"
    dynamic_key: Optional[bool]
    pwd: Optional[str]
    use_rpush: Optional[bool]
    expire_key: Optional[NonNegativeInt]
    stream_outfield: Optional[str]
    stream_capacitylimit: Optional[NonNegativeInt]


class LogOmFwd(LogOm):
    target: str = "1.2.3.4"
    port: int = 514
    enabled: bool = True
    protocol: str in ("tcp", "udp")
    zip_level: int 0 to 9


class LogOmElasticsearch(LogOm):
    servers: str = '["http://els-1:9200", "http://els-2:9200"]'
    es8_compatibility: bool = False
    data_stream_mode: bool = False
    retry_on_els_failures: bool = False
    index_pattern: str = "mylog-%$!timestamp:1:10%"
    uid: Optional[str] = ""
    pwd: Optional[str] = ""
    enabled: bool = True
    x509_certificate: Optional[int]


class LogOmMongoDB(LogOm):
    db: str = "MyDatabase"
    collection: str = "MyLogs"
    uristr: str = "mongodb://1.2.3.4:9091/?replicaset=Vulture&ssl=true"
    enabled: str = True
    x509_certificate: Optional[int]


class LogOmKafka(LogOm):
    broker: str = '["1.2.3.4:9092"]'
    enabled: bool = True
    topic: str = "MyTopic"
    key: str = ""
    dynaKey: Optional[bool]
    dynaTopic: Optional[bool]
    topicConfParam: list = []
    confParam: list = []
    partitions_useFixed: Optional[int]
    partitions_auto: Optional[bool]


class ReputationContext(BaseModel):
    name: str
    db_type: str in ("ipv4", "ipv6", "ipv4_netstet", "ipv6_netset", "domain", "GeoIP")
    method: str in ("GET", "POST")
    url: str
    verify_cert: bool = False
    post_data: str = ""
    custom_headers: dict = {}
    auth_type: str in ("", "basic", "digest")
    user: Union[str, None] = None
    password: Union[str, None] = None
    tags: list = []
    content: bytes = b""
    filename: str = ""
    description: str = ""
    last_update: str = ""
    nb_netset: str = ""
    nb_unique: str = ""
    internal: bool = False


class Backend(BaseModel):
    enabled: bool = True
    name: str
    mode: str in ("tcp", "http")
    timeout_connect: int = 2000
    timeout_server: int = 60
    headers: List[Header] = []
    custom_haproxy_conf: str = ""
    enable_tcp_health_check: bool = False
    tcp_health_check_linger: bool = True
    tcp_health_check_send: str = ""
    tcp_health_check_expect_match: str in ('', 'string', 'rstring', 'binary', 'rbinary', '! string', '! rstring', '! binary', '! rbinary')
    tcp_health_check_expect_pattern: str = ""
    tcp_health_check_interval: int = 5
    enable_tcp_keep_alive: bool = True
    tcp_keep_alive_timeout: int = 60
    http_backend_dir: str = "/"
    accept_invalid_http_response: bool = False
    http_forwardfor_header: Optional[str] = ""
    http_forwardfor_except: Optional[str]
    enable_http_health_check: bool = False
    http_health_check_linger: bool = True
    http_health_check_method: str in ("GET", "POST", "PUT", "PATCH", "DELETE")
    http_health_check_uri: str = "/"
    http_health_check_version: str in ('HTTP/1.0', 'HTTP/1.1', 'HTTP/2')
    http_health_check_headers: dict = {}
    http_health_check_expect_match: str in ("status", "rstatus", "string", "! status", "! rstatus", "! string", "! rstring")
    http_health_check_expect_pattern: str = "200"
    http_health_check_interval: int = 5
    enable_http_keep_alive: bool = True
    http_keep_alive_timeout: int = 60
    balancing_mode: str in ("roundrobin", "static-rr", "leastconn", "first", "source", "uri", "url_param", "hdr", "rdp-cookie")
    balancing_param: str = ""
    tags: list = []
    servers: list


class Server(BaseModel):
    target: str
    mode: str in ("net", "unix")
    port: int
    tls_profile: str
    weight: int
    source: str


class AccessControlLine(BaseModel):
     lines: list


class AccessControlRule(BaseModel):
    criterion: str in ("src", "base", "hdr", "shdr", "http_auth_group", "method", "path", "url", "urlp", "path", "cook", "scook", "rdp_cookie")
    criterion_name: str = ""
    converter: str in ("beg", "dir", "dom", "end", "hex", "int", "ip", "len", "reg", "str", "sub", "found")
    dns: bool = False
    case: bool = False
    operator: str in ("eq", "ge", "gt", "le", "lt", "")
    pattern: str = ""


class AccessControl(BaseModel):
    name: str
    enabled: bool = True
    or_lines: list


class BaseRepository(BaseModel):
    name: str


class OTP(BaseRepository):
    otp_type: str in ("phone", "email", "onetouch", "totp")
    otp_phone_service: str in ('authy')
    api_key: str = ""
    otp_mail_service: str in ('vlt_mail_service')
    key_length: int = 8
    totp_label: str = "Vulture App"


class LDAPCustomAttributeMapping(BaseModel):
    ldap_attribute: str = Field(regex=r"^[A-Za-z]+$")
    output_attribute: str = Field(regex=r"^[A-Za-z0-9_-]+$")


class LdapRepository(BaseRepository):
    host: str
    port: int = 389
    protocol: int = (3, 2)
    encryption_scheme: str in ('none', 'ldaps', 'start-tls')
    connection_dn: str
    dn_password: str
    base_dn: str
    user_scope: int in (0, 1, 2)
    user_dn: str
    user_attr: str = "uid"
    user_objectclasses: list = ['top', 'inetOrgPerson']
    user_filter: str = "(objectclass=person)"
    user_account_locked_attr: str = ""
    user_change_password_attr: str = ""
    user_groups_attr: str
    user_mobile_attr: str
    user_email_attr: str
    group_scope: int in (0, 1, 2)
    group_dn: str
    group_attr: str = "cn"
    group_objectclasses: list = ['top', 'groupOfNames']
    group_filter: str = "(objectClass=groupOfNames)"
    group_member_attr: str = "member"
    custom_attributes: List[LDAPCustomAttributeMapping] = []


class RepoAttributes(BaseModel):
    condition_var_kind: str in ('claim', 'repo', 'constant', 'always')
    condition_var_name: str = "email"
    condition_criterion: str in ('equals', 'not equals', 'exists', 'not exists', 'contains', 'not contains', 'startswith', 'endswith')
    assignator: str in ('=', '+=')
    condition_match: str = "test@abcd.fr"
    action_var_name: str = "admin"
    action_var_kind: str in ('constant', 'claim', 'repo', 'merge', 'claim_pref', 'repo_pref')
    action_var: str = "true"


class UserScope(BaseModel):
    name: str
    repo_attributes: list = []


class UserPortal(BaseModel):
    name: str
    enable_external: bool = False
    external_listener: Optional[str]
    external_fqdn: str = "auth.testing.tr"
    enable_tracking: bool = True
    repositories: list = []
    auth_type: str in ('form', 'basic', 'kerberos')
    portal_template: Optional[str]
    lookup_ldap_repo: str = None
    lookup_ldap_attr: str = "cn"
    lookup_claim_attr: str = "username"
    repo_attributes: list = [] # Deprecated in vulture-gui 1.2.11
    user_scope: Optional[str] # Replaces potential repo_attributes
    auth_cookie_name: Optional[str]
    auth_timeout: int = 900
    enable_timeout_restart: bool = True
    enable_captcha: bool = False
    otp_repository: Optional[str]
    otp_max_retry: int = 3
    disconnect_url: str = "/disconnect"
    enable_disconnect_message: bool = False
    enable_disconnect_portal: bool = False
    enable_registration: bool = False
    group_registration: str = ""
    update_group_registration: bool = False
    enable_oauth: bool = False
    oauth_client_id: str
    oauth_client_secret: str
    oauth_redirect_uris: list = ["https://myapp.com/oauth2/callback"]
    oauth_redirect_uris_external: list = Field([], exclude=True)
    oauth_timeout: int = 600
    enable_refresh: bool = False
    enable_rotation: bool = True
    max_nb_refresh: int = 0
    enable_sso_forward: bool = False
    sso_forward_type: str in ('form', 'basic', 'kerberos')
    sso_forward_tls_proto: str in ('tlsv13', 'tlsv12', 'tlsv11', 'tlsv10')
    sso_forward_tls_check: bool = True
    sso_forward_tls_cert: Optional[str]
    sso_forward_direct_post: bool = False
    sso_forward_get_method: bool = False
    sso_forward_follow_redirect_before: bool = False
    sso_forward_follow_redirect: bool = False
    sso_forward_return_post: bool = False
    sso_forward_content_type: str in ('urlencoded', 'multipart', 'json')
    sso_forward_url: str = "http://your_internal_app/action.do?what=login"
    sso_forward_user_agent: str = "Vulture/4 (BSD; Vulture OS)"
    sso_forward_content: str = "[{\"name\":\"csrfmiddlewaretoken;vlt;\",\"send_type\":\"form\",\"value\":\"\",\"type\":\"auto\"},{\"name\":\"token;vlt;\",\"send_type\":\"form\",\"value\":\"f5af9f51-07e6-4332-8f1a-c0c11c1e3728\",\"type\":\"oauth2_token\"},{\"name\":\"submit;vlt;\",\"send_type\":\"form\",\"value\":\"\",\"type\":\"auto\"}]"
    sso_forward_enable_capture: bool = False
    sso_forward_capture_content: str = "^REGEX to capture (content.*) in SSO Forward Response$"
    sso_forward_enable_replace: bool = False
    sso_forward_replace_pattern: str = "^To Be Replaced$"
    sso_forward_replace_content: str = "By previously captured '$1'/"
    sso_forward_enable_additionnal: bool = False
    sso_forward_additionnal_url: str = "http://My_Responsive_App.com/Default.aspx"
    sso_keep_client_cookies: Optional[bool] = True


class OPENID(BaseRepository):
    name: str
    provider: str in ('google', 'azure', 'facebook', 'github', 'keycloak', 'gitlab', 'linkedin', 'azureAD', 'MazureAD', 'openid', 'gov', 'nextcloud', 'digitalocean', 'bitbucket', 'gitea', 'digital_pass')
    provider_url: str = "https://account.google.com"
    client_id: str = ""
    client_secret: str = ""
    scopes: list = ["openid"]
    use_proxy: bool = True
    verify_certificate: bool = True
    user_scope: Optional[str]
    enable_jwt: bool = False
    jwt_signature_type: str in ('HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512')
    jwt_key: str = ""
    jwt_validate_audience: bool = True


class x509Certificate(BaseModel):
    name: str
    serial: int = 1
    status: str = "V"
    cert: str
    key: str
    chain: str
    csr: str
    crl: str
    is_ca: bool = False
    is_vulture_ca: bool = False
    is_external: bool = False
    crl_uri: str = ""
    rev_date: str = ""


    PROTOCOL_CHOICES = ("tlsv13", "tlsv12", "tlsv11", "tlsv10")
    BROWSER_CHOICES = ("advanced", "broad", "widest", "legacy", "custom")
    PROTOCOLS_HANDLER = ("advanced", "broad", "widest", "legacy")
    CIPHER_SUITES = 
    ALPN_CHOICES = 
    VERIFY_CHOICES = 

class TLSProfile(BaseModel):
    name: str
    x509_certificate: str
    compatibility: str in ('advanced', 'broad', 'widest', 'legacy')
    protocols: List[str] in ("tlsv13", "tlsv12", "tlsv11", "tlsv10")
    cipher_suite: str in ('AES128-GCM-SHA256', 'AES128-SHA', 'AES128-SHA256', 'AES256-GCM-SHA384', 'AES256-SHA', 'AES256-SHA256', 'DHE-RSA-AES128-GCM-SHA256', 'DHE-RSA-AES128-SHA', 'DHE-RSA-AES128-SHA256', 'DHE-RSA-AES256-GCM-SHA384', 'DHE-RSA-AES256-SHA', 'DHE-RSA-AES256-SHA256', 'ECDHE-RSA-AES128-GCM-SHA256', 'ECDHE-RSA-AES128-SHA', 'ECDHE-RSA-AES128-SHA256', 'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES256-SHA', 'ECDHE-RSA-AES256-SHA384', 'TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256')
    alpn: List[str] in ("h2", "http/1.1", "http/1.0")
    verify_client: str in ("none", "optional", "required")
    ca_cert: Optional[str]


class WorkflowACL(BaseModel):
    id: str
    action_satisfy: str
    action_not_satisfy: str
    redirect_url_satisfy: str = ""
    redirect_url_not_satisfy: str = ""


class Workflow(BaseModel):
    name: str
    enabled: bool = True
    frontend: str
    acl_frontend: List[WorkflowACL] = []
    acl_backend: List[WorkflowACL] = []
    authentication: Optional[str]
    fqdn: str = ""
    public_dir: str = "/"
    backend: str
    enable_cors_policy: bool = False
    cors_allowed_methods: List[str] in ('*', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'CONNECT', 'OPTIONS', 'TRACE')
    cors_allowed_origins: str = "*"
    cors_allowed_headers: str = "*"
    cors_max_age: int = 600


class Openvpn(BaseModel):
    node: str
    enabled: bool = True
    remote_server: str
    remote_port: int
    tls_profile: str
    proto: str = "tcp"


class PortalTemplate(BaseModel):
    name: str
    css: str = """/*\n * Specific styles of signin component\n */\n/*\n * General styles\n */\nbody, html {\n    height: 100%;\n    background: #FBFBF0 linear-gradient(135deg, #70848D, #21282E) repeat scroll 0% 0%;\n}\n\n.card-container.card {\n    max-width: 350px;\n    padding: 40px 40px;\n}\n\n#self_service {\n    max-width: 450px;\n    padding: 40px 40px;\n}\n\n.list-group-item {\n    text-align: left;\n}\n\n.btn {\n    font-weight: 700;\n    height: 36px;\n    -moz-user-select: none;\n    -webkit-user-select: none;\n    user-select: none;\n    cursor: default;\n}\n\n/*\n * Card component\n */\n.card {\n    text-align:center;\n    background-color: #F7F7F7;\n    /* just in case there no content*/\n    padding: 20px 25px 30px;\n    margin: 0 auto 25px;\n    margin-top: 50px;\n    /* shadows and rounded borders */\n    -moz-border-radius: 2px;\n    -webkit-border-radius: 2px;\n    border-radius: 2px;\n    -moz-box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);\n    -webkit-box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);\n    box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);\n}\n\n#vulture_img{\n    width:150px;\n}\n\n.form-signin{\n    text-align: center;\n}\n\n#captcha{\n    border:1px solid #c5c5c5;\n    margin-bottom: 10px;\n}\n\n.alert{\n    margin-bottom: 0px;\n    margin-top:15px;\n}\n\n.reauth-email {\n    display: block;\n    color: #404040;\n    line-height: 2;\n    margin-bottom: 10px;\n    font-size: 14px;\n    text-align: center;\n    overflow: hidden;\n    text-overflow: ellipsis;\n    white-space: nowrap;\n    -moz-box-sizing: border-box;\n    -webkit-box-sizing: border-box;\n    box-sizing: border-box;\n}\n\n.form-signin #inputEmail,\n.form-signin #inputPassword {\n    direction: ltr;\n    height: 44px;\n    font-size: 16px;\n}\n\ninput[type=email],\ninput[type=password],\ninput[type=text],\nbutton {\n    width: 100%;\n    display: block;\n    margin-bottom: 10px;\n    z-index: 1;\n    position: relative;\n    -moz-box-sizing: border-box;\n    -webkit-box-sizing: border-box;\n    box-sizing: border-box;\n}\n\n.form-signin .form-control:focus {\n    border-color: rgb(104, 145, 162);\n    outline: 0;\n    -webkit-box-shadow: inset 0 1px 1px rgba(0,0,0,.075),0 0 8px rgb(104, 145, 162);\n    box-shadow: inset 0 1px 1px rgba(0,0,0,.075),0 0 8px rgb(104, 145, 162);\n}\n\n.btn.btn-signin {\n    background-color: #F1A14C;\n    padding: 0px;\n    font-weight: 700;\n    font-size: 14px;\n    height: 36px;\n    -moz-border-radius: 3px;\n    -webkit-border-radius: 3px;\n    border-radius: 3px;\n    border: none;\n    -o-transition: all 0.218s;\n    -moz-transition: all 0.218s;\n    -webkit-transition: all 0.218s;\n    transition: all 0.218s;\n}\n\n.btn.btn-signin:hover{\n    cursor: pointer;\n}\n\n.forgot-password {\n    color: rgb(104, 145, 162);\n}\n\n.forgot-password:hover,\n.forgot-password:active,\n.forgot-password:focus{\n    color: rgb(12, 97, 33);\n}\n"""
    html_login: str = "<!DOCTYPE html>\n<html>\n<head>\n    <meta charset=\"utf-8\"/>\n    <title>Vulture Login</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\">\n            <form action='' method='POST' autocomplete='off' class='form-signin'>\n                <img id=\"vulture_img\" src=\"{{image_1}}\"/>\n                {% if error_message != \"\" %}\n                  <div class=\"alert alert-danger\" role=\"alert\">{{error_message}}</div>\n                {% endif %}\n                <span id=\"reauth-email\" class=\"reauth-email\"></span>\n                <input type=\"text\" name=\"{{input_login}}\" class=\"form-control\" placeholder=\"Login\" required/>\n                <input type=\"password\" name=\"{{input_password}}\" class=\"form-control\" placeholder=\"Password\" required/>\n                {% if captcha %}\n                    <img id=\"captcha\" src=\"{{captcha}}\"/>\n                    <input type=\"text\" name=\"{{input_captcha}}\" class=\"form-control\" placeholder=\"Captcha\" required/>\n\n                {% endif %}\n                <button class=\"btn btn-lg btn-warning btn-block btn-signin\" type=\"submit\">{{login_submit_field}}</button>\n                {% for repo in openid_repos %}\n                <a href=\"{{repo.start_url}}\">Login with {{repo.name}} ({{repo.provider}})</a><br>\n                {% endfor %}\n                <a href=\"{{lostPassword}}\">Forgotten password ?</a>\n            </form>\n        </div>\n    </div>\n </body>\n</html>"
    html_learning: str = "<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Learning</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\" style=\"text-align:center;\">\n            <p>Learning form</p>\n            {{form_begin}}\n                {{input_submit}}\n            {{form_end}}\n        </div>\n    </div>\n </body>\n</html>"
    html_logout: str = "<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Logout</title>\n     <link rel=\"stylesheet\" href=\"//templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n     <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\" style=\"text-align:center;\">\n            <p style=\"font-size:15px;font-weight:bold;\">You have been successfully disconnected</p>\n            <a href=\"{{app_url}}\">Return to the application</a>\n        </div>\n    </div>\n </body>\n</html>"
    html_self: str = "<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Self-Service</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\" style=\"text-align:center;\" id=\"self_service\">\n            <img id=\"vulture_img\" src=\"{{image_1}}\"/>\n            <br><br>\n            {% if error_message != \"\" %}\n                <div class=\"alert alert-danger\">{{error_message}}</div>\n            {% endif %}\n            <p>Hello <b>{{username}}</b>!</p>\n            <p>You currently have access to the following apps:</p>\n            <ul class=\"list-group\">\n                {% for app in application_list %}\n                  <li class=\"list-group-item\"><b>{{app.name}}</b> - <a href=\"{{app.url}}\">{{app.url}}</a>{% if app.status %}<span class=\"badge\">Logged</span>{% endif %}</li>\n                {% endfor %}\n            </ul>\n            <a href=\"{{changePassword}}\">Change password</a>\n            <br><a href=\"{{logout}}\">Logout</a>\n        </div>\n    </div>\n </body>\n</html>"
    html_password: str = "<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Change Password</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\" style=\"text-align:center;\">\n            <form action='' method='POST' autocomplete='off' class='form-signin'>\n                <img id=\"vulture_img\" src=\"{{image_1}}\"/>\n                {% if error_message %}\n                    <div class=\"alert alert-danger\">{{error_message}}</div>\n                {% endif %}\n                {% if dialog_change %}\n                    <p>Hello <b>{{username}}</b></p>\n                    <p>Please fill the form to change your current password :</p>\n                    {% if reset_password_key %}\n                    <input type=\"hidden\" class=\"form-control\" name=\"{{reset_password_name}}\" value=\"{{reset_password_key}}\"/>\n                    {% else %}\n                    <input type=\"password\" class=\"form-control\" placeholder=\"Old password\" name=\"{{input_password_old}}\"/>\n                    {% endif %}\n                    <input type=\"password\" class=\"form-control\" placeholder=\"New password\" name=\"{{input_password_1}}\"/>\n                    <input type=\"password\" class=\"form-control\" placeholder=\"Confirmation\" name=\"{{input_password_2}}\"/>\n                    <button class=\"btn btn-lg btn-warning btn-block btn-signin\" type=\"submit\">Ok</button>\n\n                {% elif dialog_lost %}\n                    <p>Please enter an email address to reset your password:</p>\n                    <input type=\"email\" class=\"form-control\" placeholder=\"Email\" name=\"{{input_email}}\"/>\n                    <button class=\"btn btn-lg btn-warning btn-block btn-signin\" type=\"submit\">Ok</button>\n                    \n                {% endif %}\n            </form>\n        </div>\n    </div>\n </body>\n</html>"
    html_otp: str = "<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture OTP Authentication</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body> \n    <div class=\"container\">\n        <div class=\"card card-container\" style=\"text-align:center;\">\n            {% if error_message != \"\" %}\n                  <div class=\"alert alert-danger\" role=\"alert\">{{error_message}}</div>\n            {% endif %}\n            <p>OTP Form</p>\n            <form class=\"form-signin\" autocomplete=\"off\" action=\"\" method=\"POST\">\n                {% if onetouch %}\n                  {{otp_onetouch_field}}\n                {% else %}\n                <input type=\"text\" name=\"vltprtlkey\" class=\"form-control\" placeholder=\"Key\" required/>\n                <button class=\"btn btn-lg btn-warning btn-block btn-signin\" type=\"submit\">{{otp_submit_field}}</button>\n                {% endif %}\n            </form>\n            <form class=\"form-signin\" autocomplete=\"off\" action=\"\" method=\"POST\">\n                {% if resend_button %}\n                    <button class=\"btn btn-lg btn-warning btn-block btn-signin\" name=\"{{input_otp_resend}}\" value=\"yes\">{{otp_resend_field}} {{otp_type}}</button>\n                {% endif %}\n                {% if qrcode %}\n                    <p>Register the following QRcode on your phone :\n                    <img src=\"{{qrcode}}\" alt=\"Failed to display QRcode\" height=\"270\" width=\"270\" />\n                    </p>\n                {% endif %}\n            </form>\n        </div>\n    </div>\n </body>\n</html>"
    html_message: str = "<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Info</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\">\n            <img id=\"vulture_img\" src=\"{{image_1}}\"/>\n            <p>{{message}}</p>\n            {% if link_redirect %}<a href=\"{{link_redirect}}\">Go back</a>{% endif %}\n        </div>\n    </div>\n </body>\n</html>"
    html_error: str = "<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Error</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>\n        <style>{{style}}</style>\n    </style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\">\n            <img id=\"vulture_img\" src=\"{{image_1}}\"/>\n            <p>{{message}}</p>\n        </div>\n    </div>\n </body>\n</html>"
    html_registration: str = "<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Registration</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\" style=\"text-align:center;\">\n            {{form_begin}}\n                <img id=\"vulture_img\" src=\"{{image_1}}\"/>\n                {% if error_message %}\n                    <div class=\"alert alert-danger\">{{error_message}}</div>\n                {% endif %}\n                {{captcha}}\n                {{input_captcha}}\n                {% if step2 %}\n                    <p>Please fill the form to register your account :</p>\n                    {{input_username}}\n                    {% if ask_phone %}\n                    {{input_phone}}\n                    {% endif %}\n                    {{input_password_1}}\n                    {{input_password_2}}\n                    {{input_submit}}\n\n                {% elif step1 %}\n                    <p>Please enter your email address to receive the registration mail :</p>\n                    {{input_email}}\n                    {{input_submit}}\n                {% endif %}\n            {{form_end}}\n        </div>\n    </div>\n </body>\n</html>"
    html_error_403: str = "403 Forbidden"
    html_error_404: str = "404 Not Found"
    html_error_405: str = "405 Method Not Allowed"
    html_error_406: str = "406 Not Acceptable"
    html_error_500: str = "500 Server Error"
    html_error_501: str = "501 Not Implemented"
    html_error_502: str = "502 Bad Gateway"
    html_error_503: str = "503 Service Unavailable"
    html_error_504: str = "504 Gateway Time-out"
    email_subject: str = "Password reset request for {{ app.name }}"
    email_body: str = "<html>\n<head>\n</head>\n<body>\n<p>Dear Sir/Madam <b>{{username}}</b>, <br><br>\n\nWe got a request to reset your account on {{ app.url }}.<br><br>\n\nClick here to reset your password: <a href=\"{{resetLink}}\">Reset password</a><br><br>\n\nIf you ignore this message, your password won't be changed.<br>\nIf you didn't request a password reset, <a href=\"mailto:abuse@vulture\">let us know</a><br>\n</body>\n</html>"
    email_from: str = "no-reply@vulture"
    error_password_change_ok: str = "Your password has been changed"
    error_password_change_ko: str = "Error when trying to change your password"
    error_email_sent: str = "An email has been sent to you with instructions to reset your password"
    email_register_subject: str = "Registration request for {{ app.name }}"
    email_register_from: str = "no-reply@vulture"
    email_register_body: str = "<html>\n    <head>\n        <title>Vulture registration</title>\n    </head>\n    <body>\n        <p>Dear Sir/Madam <b>{{username}}</b>, <br><br>\n\n        We got a request to register your account on {{ app.url }}.<br><br>\n\n        Click here to validate the registration : <a href=\"{{registerLink}}\">Register account</a><br><br>\n\n        If you ignore this message, your account won't be confirmed.<br>\n        If you didn't request a registration, <a href=\"mailto:abuse@vulture\">let us know</a><br>\n    </body>\n</html>"
    login_login_field: str = "Login"
    login_password_field: str = "Password"
    login_captcha_field: str = "Captcha"
    login_submit_field: str = "Sign in"
    learning_submit_field: str = "Save"
    password_old_field: str = "Old password"
    password_new1_field: str = "New password"
    password_new2_field: str = "Confirmation"
    password_email_field: str = "Email"
    password_submit_field: str = "OK"
    otp_key_field: str = "Key"
    otp_submit_field: str = "Sign in"
    otp_resend_field: str = "Resend"
    otp_onetouch_field: str = "<p>Please approve the OneTouch request on your phone, and click on 'Sign in'</p>"
    register_captcha_field: str = "Captcha"
    register_username_field: str = "Username"
    register_phone_field: str = "Phone number"
    register_password1_field: str = "Password"
    register_password2_field: str = "Password confirmation"
    register_email_field: str = "Email"
    register_submit_field: str = "Register"


class Ipsec(BaseModel):
    node: str
    enabled: bool = False
    ipsec_type: str in ('tunnel')
    ipsec_keyexchange: str in ('ikev2')
    ipsec_authby: str in ('secret')
    ipsec_psk: str
    ipsec_fragmentation: bool = True
    ipsec_forceencaps: bool = False
    ipsec_ike: str = 'aes256-sha512-modp8192'
    ipsec_esp: str = 'aes256-sha512-modp8192'
    ipsec_dpdaction: str = 'restart'
    ipsec_dpddelay: str = '35s'
    ipsec_rekey: bool = True
    ipsec_ikelifetime: str = '3h'
    ipsec_keylife: str = '1h'
    ipsec_right: str
    ipsec_leftsubnet: str
    ipsec_leftid: str
    ipsec_rightsubnet: str
