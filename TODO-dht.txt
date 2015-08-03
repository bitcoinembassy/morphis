* _store_data(..) code needs to be fixed to use an additional table, something like DataBlockJournal, which tracks pending deletes or creations, thus ensuring the filesystem is kept in sync, even if crashes, Etc.

+ Add code to opportunistically store data passing through if it is wanted. This will make data spread by popularity and not need constant uploading to prevent from dropping off the network.

- Needs an insert time prefix/suffix to the key so to efficiently reduce the chance of collisions.

- rewrite the connection code (meaning the code that decideds who to try to connect to). It was my first attempt at doing complex concurrent stuff with asyncio, and is a bit wonky and very slow. It for instance tries to connect to the same Peer in a row multiple times. It should try to minimize using so many transactions. Etc.

- have the shell channel open code mark this dbpeer as a shell client and from then on only let the peer with that id (client pubkey authenticated with) open a session channel.

- consider morphis/ssh protocol disconnect message as authentic. consider tcp disconnect as ddos and simply reconnect. (issue with one host firewalled, thus only connecting host can reconnect). have some sanity to prevent loop.

- have tunnels relay data if they've already seen it so that we don't have to send it the whole way from us for each destination.
