# Mod Defender
filtering on Vulture 4 relies currently on **<a href="https://github.com/VultureProject/mod_defender" target="_blank">Mod Defender</a>**.  

Mod Defender is an almost complete replication of **[NAXSI](https://github.com/nbs-system/naxsi)**, a whitelist-policy filtering module for Nginx: it relies on very simple rules to block potentially dangerous queries. Then, by explicitely allowing patterns, the filtering rules are "loosened" to fit the website's needs.  

These rules are the building blocks necessary to adapt the filtering to your specific workflow(s). When assigned to a Workflow though a **[WAF policy](/darwin/defender_policy)**, they allow specific requests to be blocked or to pass depending on the application needs.  


# Automatic whitelisting Rules creation
In Vulture 4, you can also simplify your whitelisting generation by using the integrated features:
1. Create a **[WAF Policy](/darwin/defender_policy/)** with a basic set of whitelisting Rulesets
2. Assign that Policy to the Workflow(s) you want to filter
3. Check that *Store logs into cluster database* option is enabled in the Listener(s) concerned by the Workflow(s), to provide all logs in MongoDB
4. Begin browsing and using your Workflow, sometimes encountering 403 when Mod Defender blocks queries
5. After a first pass with some 403, go to the Reverse Proxy section corresponding to your Workflow(s) in the **[Low Viewer](/darwin/logviewer/)**
6. You should have logs with a *defender_score* at 403, from here you can click on the **Generate learning logs** to see the list of requests blocked by Mod Defender
7. From this list, you can select (and potentially merge) rules you wan't whitelisted (look at the LogViewer documentation to get more details)
8. Add thoses rules to the corresponding WAF Ruleset
9. Go back to point 4, check old 403 are gone and continue the process again to find new undesired filtering cases
