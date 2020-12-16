# Multi-Tenants config

Vulture is designed to manage several "contexts" within a given Cluster. This allows service providers to deliver services for differents customers, with different functionalities on a mutualized Vulture cluster.

In a log management scenario, it allows vulture to "tag" logs with information relative to a specific customer. In particular, you can use different enrichment databases for each of the customer.

## Tenants list

### Name

This is the tenant friendly name that Vulture will add in any logs or alert

### Associated reputation context

This is the list of all Cyber Threat Intelligence feeds (IP, domains, URL, Hashes, IOC...) available to the tenant. Vulture uses the "Predator" web service with a community or enterprise Vulture version.

You can add custom feed by adding them via the [Context Tags](apps/reputation_ctx) menu.

### Associated listeners

Here you have an overview of listeners associated to this tenant

### Action

Here you can duplicate the tenant config or delete the tenant
