# vlt-admin CLI

The `vlt-admin` cli tool is installed through the **vulture-utils** package and is available from any user.

This tool allows to handle safe and efficient upgrades,as well as system snapshotting and rollbacking.

# sub-commands

The `vlt-admin` CLI possess a list of available sub-commands, each with their own role:

1. **upgrade-os**: this sub-command allows to handle OS upgrades, as well as jails' base
1. **upgrade-pkg**: this sub-command allows to handle upgrades of all or specific packages, as well as packages in specific jails
1. **snapshot**: this sub-command allows to create snapshots of all or specific parts of the system
1. **restore**: this sub-command allows to use created snapshots (through the **snapshot** sub-command) to rollback all or parts of the system

## Upgrading the OS

The `upgrade-os` is the command that allows to upgrade the base system, the kernel and the jails' base system.

This command can:

- Upgrade base/kernel of the host
- Upgrade all or some of the jails' base system
- Use Boot Environments to install and validate host's upgrades

To get a list of possible options and their description, you can run `vlt-admin upgrade-os -h`.

Here are some examples of use-cases and their corresponding commands:

| Use case | command |
| -------- | ------- |
| Upgrade host and jail's base system and kernel, in place | `vlt-admin upgrade-os all` |
| Upgrade jail's base system, in place | `vlt-admin upgrade-os jails` |
| Upgrade the apache jail's base system, in place | `vlt-admin upgrade-os apache` |
| Download and install the host's base and kernel, in a Boot Environment, applied on reboot | `vlt-admin upgrade-os -b` |
| Install a specific host's kernel and base, in place | `vlt-admin upgrade-os -B -V <version>` |
| Download the latest upgrade base + kernel, and keep it in the /var/tmp/upgrade directory | `vlt-admin upgrade-os -D -T -t /var/tmp/upgrade` |
| Upgrade host and jail's base system and kernel, using previously downloaded archive in /var/tmp/upgrade | `vlt-admin upgrade-os -B -T -t /var/tmp/upgrade` |

## Upgrading packages

The `upgrade-pkg` is the command that allows to upgrades packages, either on the system and/or in the jails.

This command can:

- Upgrade all host and jails' packages
- Upgrade all packages in a specific jail
- Upgrade specific packages on the system

To get a list of possible options and their description, you can run `vlt-admin upgrade-pkg -h`.

Here are some examples of use-cases and their corresponding commands:

| Use case | command |
| -------- | ------- |
| Upgrade all installed packages, on the host and in every jail | `vlt-admin upgrade-pkg` |
| Upgrade all packages in the haproxy jail, as well as vulture-haproxy | `vlt-admin upgrade-pkg haproxy` |
| Upgrade the sudo and vim packages | `vlt-admin upgrade-pkg sudo vim` |
| Upgrade all packages in the gui jail, as well as vulture-gui and the vulture-base packages | `vlt-admin upgrade-pkg gui base` |
| Only download the latest packages for the rsyslog jail | `vlt-admin upgrade-pkg -D rsyslog` |

## Snapshotting and Restoring the system

In addition to the Boot Environment feature for OS upgrades, it's also possible to snapshot all or parts of the system.

These commands use the **ZFS filesystem** and **Boot Environments** to create, rollback and destroy snapshots.

The snapshotting process is done by the `vlt-admin snapshot` subcommand, and the following *datasets* can be snapshotted:

- SYSTEM: This dataset only represents part of the base OS, this is the dataset that is currently mounted on '/'
- JAILS: This represents all datasets making up the base system of every jail ('/' and '/usr/')
- HOME: This represents the /home dataset
- DATABASE: This represents the dataset(s) containing the Vulture's database(s)
- TMPVAR: This represents all datasets containing variable and temporary data

To snapshot, you simply have to run the `vlt-admin snapshot` command and specify the flag(s) corresponding to each dataset.

Each dataset's flag is defined by its first letter in uppercase.
For example, to snapshot **S**YSTEM, **J**AILS and **D**ATABASE, the command to run would be

> `vlt-admin snapshot -S -J -D`.

You can also specify the `-A` flag to snapshot **ALL** datasets.

To avoid taking too much disk space with saved snapshots, you can additionally add the `-k` flag with a positive number 
to restrict each dataset's number of snapshots to the specified number.
For example, to run the previous snapshotting command while ensuring only the 3 latest snapshots remain,
the command to run would be

> `vlt-admin snapshot -S -J -D -k 3`

### The rollbacking process

When snapshots exist, you can list them using the `-l` flag:

> `vlt-admin snapshot -l`

You can then use them to rollback all or parts of the datasets, using the same set of flags to select parts to rollback.
For example, to restore the datasets snapshotted on the previous example to their latest snapshotted state:

> `vlt-admin restore -S -J -D`

Once datasets' snapshots are triggered for restore, the pending restores can be shown with:

> `vlt-admin restore -l`

**WARNING**: existing snapshots won't be shown using this command, only those triggered for the restoration process will be!

To execute a restore, some prerequisites are still necessary after triggering:

- the *zfs_restore* service should be enabled (this is done by default)
- the machine should be **restarted** after the trigger(s)

When triggering the wrong snapshots, you can simply reset some or all triggers with a single command.
For example, if the databases' dataset was set but should not, you can simply:

> `vlt-admin restore -D -c`

By default, the latest snapshot is used for every dataset, but you can select any previous one by specifying it with the '-r' flag.
For example, when listing existing snapshots with `vlt-admin snapshot -l`, assuming this reply:

```
SYSTEM: VLT_SNAP_2024-07-10T16:42:07
JAIL:   VLT_SNAP_2024-07-10T16:42:07    VLT_SNAP_2024-07-10T16:19:14
DB:     VLT_SNAP_2024-07-10T16:42:07
HOMES:  VLT_SNAP_2024-07-10T16:42:07
TMPVAR:
```

The *VLT_SNAP_2024-07-10T16:19:14* snapshot on JAIL's dataset can be restored using:

> `vlt-admin restore -J -r VLT_SNAP_2024-07-10T16:19:14`

**Warning**: Specifying snapshot names' that don't exist for some datasets will result in a failure!

# Use cases

## Safe OS upgrade

To safely upgrade the host's base and kernel, you can use the Boot Environment feature 
to install the upgrade in a separate environment and only activate/validate it once the machine is rebooted.

This setup will prevent changing anything from the currently running system, while still downloading and installing 
the OS upgrade on the machine.

To do that, simply run

> `vlt-admin upgrade-os -b`

This will

1. Download the base/kernel upgrade on the machine
2. Create a new [Boot Environment](https://wiki.freebsd.org/BootEnvironments)
3. Install the upgrade on it
4. Activate the BE for next reboot if everything ran correctly

By using this method:

- Running system is not changed in any way
- Upgraded system is still downloaded and installed on the machine
- The maintenance window for the machine is limited to a single reboot
- If something went wrong, the old environement can be reset with [bectl](https://man.freebsd.org/cgi/man.cgi?bectl(8))

**Important to note**: by doing that, neither jail's base nor packages will be upgraded, 
read next section.

## Safe jails/packages upgrades

Using the snapshot/restore capabilities of *vlt-admin*, jails and packages can also be safely restored 
to their previous state.

To do that, it is possible to:

- Snapshot all necessary datasets
- Execute the upgrades
- Validate the upgrade
- If something went wrong, rollback all snapshotted datasets to their previous state

To do that, simply run:

- `vlt-admin snapshot -S -J -H -D`: to snapshot datasets related to an OS and packages upgrade
- `vlt-admin upgrade-os jails`: to upgrade jails' base system
- `vlt-admin upgrade-pkg`: to upgrade base system and jails' packages

And to rolback if something went bad:

- `vlt-admin restore -S -J -H -D`: trigger snapshots to restore
- `reboot`: restart the machine to execute restores

**Warning**: Many Vulture package upgrades do change parts of the database, but snapshotting it through filesystem 
on a clustered environment won't restore the database as the other nodes will hold updated data.
When doing these steps on a clustered environement, the best thing to do is use mongo tools to dump the database 
and don't snapshot the databases dataset (thus dropping the `-D` from previous commands).
