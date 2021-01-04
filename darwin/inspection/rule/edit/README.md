
## Editing
When clicking a row, the corresponding Inspection Rule can be edited.  
- Its name can be set/changed (spaces will be replaced by underscores)
- Its techno can be set/changed
- Its category can be set/changed
- Its content can be set/changed (this should respect the techno's syntax)


# Inspection Rule Edition
When clicking a row, the corresponding Inspection Rule can be edited.  

## Name
The name represents a simple identifier for your rule.  
It **cannot contain any spaces** (they will be replaced by underscores) and must be **unique** among your list of Rules.

## Techno
This represents the engine technology for the detection.  
Currently, Inspection Rules only support **yara** as a techno, but this could change.

## Category
This is a text area to **classify** your rule.  
This is useful to know from which category a rule from GitHub comes from.

## Content
This field is a text area to enter the **content** of your rule.  
Its **syntax will be checked** when a policy is created with this rule.