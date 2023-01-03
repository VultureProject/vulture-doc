# Inspection Policy Edition
When clicking a row, the corresponding Inspection Policy can be edited.  

## Name
The name represents a simple identifier for your policy.  
It cannot contain any spaces (they will be replaced by underscores) and must be unique among your list of policies.

## Techno
This represents the engine technology for the detection.  
Currently, Inspection Policies only support **yara** as a techno, but this could change.

## Description
This is a text area to describe your policy with more **details**.

## Status
This field is shown only when creating a new Policy or when there is a syntax error.  
The status **shows any error** that could occur during syntax check using the technology engine.

## Rules
This is the list of Rules to include in the policy.  
Only Inspection Rules of the same technology will be available when selecting.  
Rules can be filtered by name when you write down their name as part or whole in the list.

- Its **name** can be set/changed (spaces will be replaced by underscores)
- Its **techno** can be set/changed (currently, only *yara* is available)
- Its description can be set/changed
- Its status can be shown, if the Policy is new or there was errors during syntax check.
- The list of Inspection Rules used can be set (only Inspection Rules of the same technology will be shown)

# Syntax check
After being saved, the Policy's syntax will be checked in the background using the technology's engine, if something is wrong the status will show it in the list page and *status* will be visible and show the error(s) in the edit page.
