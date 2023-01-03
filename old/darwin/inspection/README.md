# Detection
To get a full understanding of Yara's possibilities and rule writing, please visit __[their documentation](https://yara.readthedocs.io/en/stable/)__.  
On Vulture, by using **Yara with Darwin** users can perform detections on a **large variety of data**, with **various objectives**:
- malware detection
- URL requests content
- specific domain names patterns uses
- username/hostname with incorrect/unmanaged pattern
- specific sentences in mails, text, etc...



# Inspection Policies
This tab lists all the configured Inspection Policies.  
Those policies represent a group of __[Yara](https://yara.readthedocs.io/en/stable/)__ Rules, used by __[Darwin policies](/darwin/policy/)__ in yara filters to **detect patterns in raw data**.  

## List fields
In the table, you have the **list of all your configured Inspection Policies**, each row contains various information.

### Last update
This is the **last time the policy has been modified**.

### Name
This is the **name** of the policy.  
Names should be **unique among all policies**, spaces will be automatically replaced by underscores.

### Status
Indicates if the policy is **correct/can be used**.  
**Policies' syntax is tested every time after save**, if the syntax is wrong the policy cannot be used and the status will indicate an error.  
**Errors can be seen when editing the policy**.

### Techno
This is the **technology** used by this policy. the only techno available at the time is **yara**.

### Description
The description lets you provide **details** on the goal and specifics of this Inspection Policy.

### Actions
#### Copy
You can quickly open an edition page with a **new Inspection Policy cloned from an existing policy** by clicking this button.  
Copying can let you save variants of a policy for **testing** of **versionning**.

#### Delete
This **removes** the policy.

# Inspection Rules
This tab list all the created Inspection Rules.  
Thoses Rules are **used to create inspection Policies**.  

## Update rules online
This tab presents a button to update rules online, this action allows to **download default Yara rules from a <a href="https://github.com/Yara-Rules/rules" target="_blank">github repository</a>**.  
The action will **run in the background**, users should check its status in the **notification zone** (in the upper-right corner).  
When the update is finished, **default policies will also be created/updated**.

## List Fields
In the table, you have the list of all your configured Inspection Rules, each row contains various information.

### Last update
This is the **last time the rule has been modified**.

### Name
This is the name of the rule.  
Names **should be unique among all rules**, spaces will be automatically replaced by underscores.

### Techno
This is the **technology** used by this rule. the only techno available at the time is **yara**.

### Category
This is a **classification category** for the rule.

### Source
This field tells if the rule was **imported from GitHub**, or if it was created **manually**.

### Actions
#### Copy
You can quickly open an edition page with a **new Inspection Rule cloned from an existing rule** by clicking this button.  
Copying can let you save variants of a rule for **testing** of **versionning**.

#### Delete
This **removes** the rule.
