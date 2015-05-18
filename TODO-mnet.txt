* Need to implement ssh re-keying.

* Have local_cid an object that is unique so that closed channels are safe forever to call stuff on (and get exceptions and not misbehavior).

- add feature to morphis-ssh to be able to resume an ssh session with 0 protocol overhead. Ie: if tcp disconnects, simply tcp connect again and continue as if nothing happened (ssh session never died, keys reused, etc).
