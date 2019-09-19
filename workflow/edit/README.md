## WORKFLOW

---
Workflows allow you to link your **[LISTENERS](/services/frontend/)** with your **[APPLICATIONS](/apps/backend/)**.

You can only link **HTTP** or **TCP** Listeners and Applications.

### HOW TO

---
First, you'll need to choose a Listener from the left block (double click on one to add it to the workflow).

If you select a **HTTP Listener**, a prompt will ask you the **FQDN** and the **Public Directory** (The public path of your application. Default is '/'.) to listen to.

Once the Listener is selected, the left block reloads with **[ACLs](/darwin/acl/)** and **Defender Policy**. 

You can add as many **[ACLs](/darwin/acl/)** as you need, they will be configured in the **Frontend configuration of HAProxy**.   

Then select a **[Defender Policy](/darwin/defender_policy/)**. If you don't want a Policy, select the **No policy** entry.

You can add more **[ACL](/darwin/acl/)** after the **Defender Policy**, they will be configured in the **Backend configuration of HAProxy**.

To finish the **Workflow** you will need to select a Backend 


### Access Control List

---
Every time you choose an **[ACL](/darwin/acl/)**, a prompt will ask you the desired operation with this [ACL](/darwin/acl/). You can choose an action if the **[ACL](/darwin/acl/)** **satisfy** or **don't satisfy**.

The possible actions are: 

* **200 Continue**
* **403 Forbidden**
* **302 Redirect**
* **301 Permanent Redirect**

At least one action must be a **CONTINUE** response.

When you select the **301** or **302** action, you'll need to fullfill the **URL to redirect to**.

