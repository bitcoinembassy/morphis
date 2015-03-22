import chord_packet as cp

class ChordTasks(object):
    def __init__(self, engine):
        self.engine = engine
        self.loop = engine.loop

    @asyncio.coroutine
    def _do_stabilize(self):
        new_nodes = bittrie.BitTrie()

        maximum_tasks = 3
        tasks = []

        used_peers = bittrie.BitTrie()

        for peer in self.engine.peer_trie:
            if not peer:
                continue

            key = bittrie.XorKey(self.engine.node_id, peer.node_id)
            item = [peer, None]
            new_nodes[key] = item

            if len(tasks) == maximum:
                continue
            if not peer.ready:
                continue

            used_peers[self.engine.node_id] = peer

            tasks.append(\
                asyncio.async(\
                    self._send_find_node(peer, new_nodes), loop=self.loop))

        done, pending = yield from asyncio.wait(tasks)
        tasks.clear()

        cnt = 0

        for row in new_nodes:
            if not new_nodes:
                continue
            if row[1] is None:
                # Already asked direct peers.
                continue

            peer, idx, tun, queue, local_cid = row

            msg = cp.ChordRelay()
            msg.index = idx

            tun.protocol.write_channel_data(local_cid, msg.encode())

            r = used_peers.setdefault(tun.node_id, tun)
            if r:
                # We already have a process task running for this node.
                continue

            tasks.append(\
                asyncio.async(\
                    self._process_find_node_relay(row, new_nodes)))

            cnt += 1
            if cnt == maximum:
                break

        #TODO: YOU_ARE_HERE: Add all results to trie and loop again until no more closer ones.

    @asyncio.coroutine
    def _process_find_node_relay(self, row, result_trie):
        peer, idx, tun, queue, local_cid = row

        while True:
            pkt = yield from queue.get()

            if

    @asyncio.coroutine
    def _send_find_node(self, peer, result_trie):
        local_cid, queue =\
            yield from peer.protocol.open_channel("mpeer", True)
        if not queue:
            return

        msg = cp.ChordFindNode()
        msg.sender_port = self.engine._bind_port #FIXME: Put elsewhere.
        msg.node_id = self.engine.node_id

        peer.protocol.write_channel_data(local_cid, msg.encode())

        pkt = yield from queue.get()
        if not pkt:
            return

        msg = cp.ChordPeerList(pkt)

        idx = 0
        for rpeer in msg.peers:
            key = bittrie.XorKey(self.engine.node_id, peer.node_id)
            result_trie.setdefault(key, [rpeer, idx, peer, queue, local_cid])
            idx += 1
