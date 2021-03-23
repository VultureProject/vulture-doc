# WAF Policy
This is where you'll be able to define what protections to activate inside a **WAF Policy**.  
This policy will then be available to use with **[Workflows](/workflow/)** to block and protect your websites.

## Name
This is the name of your Policy, used to identify it from all the others.  
The name can contain spaces, but must be unique among all your policies.

## Request Body Limit
That parameter limits the analyse of bodies in POST/PUT requests to a certain size.  
If the size of the received request body is over **RequestBodyLimit**, the body is not analysed (other zones will still be scanned).  

## Libinjection
Mod Defender leverages the **[libinjection library](https://github.com/client9/libinjection)** to detect most SQL and XSS patterns and block them.  
It is directly integrated with the detection features to efficiently detect advanced SQLi and XSS patterns in requests, and works out of the box to provide additional security to your WAF.  
You can enable libinjection for **SQLi detection**, **XSS detection**, or **both**.  

## WAF Ruleset
**[Rulesets](/darwin/defender_ruleset/)** are the rules that allow to specify what should be allowed to pass and what shouldn't in your **[WAF Workflows](/workflow/)**, they can be edited to fit your needs in **[their own view](/darwin/defender_ruleset/)**, but you have to assign your rules to a detection policy here.  
