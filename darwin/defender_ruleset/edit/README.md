# WAF Ruleset
This is where you can view and modify your existing Rulesets.  
The Rulesets contain all your blacklisting/whitelisting Rules, that you can then use in **[WAF Policies](/darwin/defender_policy)** to filter-out threats from your legitimate website traffic.  

The Rules are written using **[NAXSI](https://github.com/nbs-system/naxsi)** syntax, and are fully compatible with rules generated using **[NXAPI/NXTOOL](https://github.com/nbs-system/naxsi/tree/master/nxapi)**.
You can also generate Rules automatically from the **[Log Viewer](/dawin/logviewer/)**.  

## Blacklist Rules - MainRule
Those rules are here to **block** requests, they work by assigning a score on a pattern and each match to one of them increments a counter corresponding to the threat. As soon as a counter reaches the blocking threshold, the request is dropped.  
Vulture 4 [integrates default MainRules](https://github.com/VultureProject/vulture-base/blob/master/usr/local/etc/defender.d/core.rules) taken from NAXSI core rules, those rules contain:
- formatting errors (wrong encodings, empty POSTs, invalid JSONs, etc...)
- SQL injections
- Obvious Remote File Inclusions (RFI)
- Directory traversal
- Cross-Site Scripting (XSS)
- Evasion tricks (encoding)
- File uploads

### Syntax
A **MainRule** block has the following format:  
`MainRule <negative> "str/rx:<pattern_to_match>" "msg:<message>" "mz:<zone_to_inspect>" "s:<score>" id:<rule_number>;`  
- **pattern_to_match:** The pattern to match may be a regular expression (regex) or a string:
    - `rx:foo|bar` : String "foo" or string "bar"
    - `str:foo|bar` : String "foo|bar".
    - `d:libinj_sql` : Scan for generic SQL injection patterns, using libinjection SQL
    - `d:libinj_xss` : Scan for generic XSS injection patterns, using libinjection XSS
    - Use **string patterns** instead of regex when possible, this is **faster**.
    - All strings must be written in **lowercase** as mod_defender converts them to lowercase before processing.

- **message:**
    - `msg` is a message that describes the rule in a comprehensive manner.
    - This attribute is used in logs when a rule matches and is only here to explain the block reason.

- **zone_to_inspect:** `mz` means "match zone". It tells mod_defender where to look for the pattern.
    - `mz:BODY|URL|ARGS` means that the *BODY*, the *URL* (before the '?') and *GET* variables will be inspected
    - `mz:$HEADERS_VAR:Cookie` means that the rule will inspect the "**Cookie**" *HTTP HEADER*
    - `mz:$URL:/login|$ARGS_VAR:username` means that the GET parameter 'username' will be inspected when the request URL is '/login'
	- Name and extension of files may be specified in the zone FILE_EXT to inspect request during a file upload.

- **score** `s` tells mod_defender which counter to increase, and by which amount, when the rule matches. A rule may increment several counter at once.
    - `s:$SQL:8` will add '8' to the '$SQL' counter.
    - `s:$SQL:4,$XSS:4` will add '4' to the '$SQL' counter and '4' to the '$XSS' counter.
    - In the score rule, one can also use one of the following action: BLOCK, DROP, ALLOW or LOG. The action will be applied when the pattern matches.

- **rule_number**
    - `id` is the rule number which will be used by other basic rules to refer to this rule. The rule number is also present in logs when the rule matches.

- **negative**
    - It is possible to add the `negative` keyword to invert the action of the rule, so that the score will be applied if the rule does not match.


## Whitelist Rules - BasicRule
In addition to the **Main Rules** that filter out dangerous requests, Mod Defender uses **Basic Rules** to explicitely **whitelist** requests you want to allow for your website. These rules are unique to the website to protect and can be declared manually or automatically through the **[Low Viewer](/darwin/logviewer/)**.  

### Syntax
A **BasicRule** block has the folowing format:  
`BasicRule wl:<disabled_id> "mz:<zones to inspect>"`  

- **disabled_id**
    - Tells mod_defender to deactivate blocking main rules. Main rules to deactivate are referenced by their respective ids.
    - `wl:1000` disable the rule n°1000
    - `wl:1000,1001,1002` disable rules n°1000, 1001 and 1002
    - `wl:-1000` disable all rules except rule n°1000 and internal rules

- **Zone to inspect**
    - `mz` means "match zone". It tells mod_defender where to look for patterns. Match zone is optional: If not specified, the basic rule will apply to all request's zones. Available match zones are :
        - `ARGS` : all GET parameters
        - `$ARGS_VAR:<value>` : a specific GET parameter
        - `$ARGS_VAR_X:<regex>` : specific GET parameter(s) matching regex
        - `HEADERS` : all HTTP headers
        - `$HEADERS_VAR:<value>` : a specific HTTP header
        - `$HEADERS_VAR_X:<regex>` : specific  HTTP header(s) matching regex
        - `BODY` : BODY of a POST / PUT request
        - `$BODY_VAR:<value>` : a parameter that belongs to the body of a POST / PUT request
        - `$BODY_VAR_X:<regex>` :  specific parameter(s) that belongs to the body of a POST / PUT request matching regex
        - `URL` : URL of the asked resource, before the '?'
        - `$URL:value` : Specific URL
        - `$URL_X:<regex>` : Regex that applies to the URL
        - `FILE_EXT` : Name of the file uploaded during a multipart POST request
        - A match zone may be followed by "|NAME". This means that the rule will only apply on the variable's name - and not on its value. Match zones must be written in lowercase.