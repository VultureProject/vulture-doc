# Introduction to Salt

## Presentation

SaltStack is an OpenSource software written in python and owned by VMware.

It is used maily to manage configuration and executing remote tasks.

## How it works

Based on Server-Client communication using a publish-subscribe pattern. It can deploy configurations on a large scale infrastructure through Salt minions (be shure to open ports 4505 and 4506 on the master side).

Salt minions do their own work. Communication from the Salt master is a lightweight set of instructions. They determine locally if they match the properties when the command is received.

Each Salt minion already has all of the commands that it needs, so the command can be executed and the results return back to the Salt master.

The scalability is very impressive with Salt, it is not uncommon to meet users with over 10,000 minions on a single master in production.

A minion needs to send his public key to the master and it returns back an AES key, encrypted by the minions key.

## Integration in Vulture

We use Salt mainly for the fast and automated deployement of complex configurations. But also to check local files or installed packages.
