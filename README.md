# HIBA: Host Identity Based Authorization

## What is HIBA

HIBA is a system built on top of regular OpenSSH certificate based
authentication that allows to manage flexible authorization of principals on
pools of target hosts without the need to push customized authorized_users files
periodically.

The authorization is performed directly on the target host based on the user
certificate content and the local host identity only. Not accessing external
services makes it suitable for low dependency, last resort, SSH access.
