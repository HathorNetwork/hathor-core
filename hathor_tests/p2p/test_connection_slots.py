from twisted.python.failure import Failure

from hathor.p2p.connection_slot import ConnectionState, ConnectionType, SlotsManager, SlotsManagerSettings
from hathor.simulator import FakeConnection
from hathor.simulator.fake_connection import IPv4Address
from hathor_tests.simulation.base import SimulatorTestCase


class ConnectionSlotsTestCase(SimulatorTestCase):
    def test_slot_limit(self) -> None:
        """ Tests whether the slots and the pool stop increasing connections after cap is reached.

            Important note: create_peer caps the peer pool at 100. Hence, if more than 100 connections
            are opened (if settings.P2P_..._OUTGOING + settings.P2P_...INCOMING _+ ... exceed 100)
            then the tests will fail."""

        # Full-Node: May receive incoming connections, deliver outgoing connections, etc.
        # If the total amount of connections exceeds 100, create_peer will not yield more than 100 peers as well.
        full_node = self.create_peer()

        # Set the limits for each slot (sum MUST NOT exceed 100).
        # We set the limits here since grabbing the values from the settings exceeds limits in simulator.
        max_outgoing = 20
        max_incoming = 15
        max_bootstrap = 10
        max_check_ep = 5
        max_queue_ep = 100
        max_connections = max_bootstrap + max_incoming + max_outgoing + max_check_ep

        # Set SlotsManager Settings:
        sm_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap, max_check_ep, max_queue_ep)

        # Set SlotsManager:
        slots_manager = SlotsManager(sm_settings)

        # Attribute it to the peer
        full_node.connections.slots_manager = slots_manager

        # For each connection type we add more peers than necessary to see if the slot limits it.
        # Create peer list for incoming connections
        in_peerList = []
        in_connList = []
        for i in range(0, max_incoming):
            in_peerList.append(self.create_peer())

            # Generate incoming connections - full_node is the target.
            in_connList.append(FakeConnection(full_node, in_peerList[i]))

            # Add connections to simulator.
            self.simulator.add_connection(in_connList[i])

        self.simulator.run(10)

        incoming_slot = full_node.connections.slots_manager.incoming_slot
        number_incoming_slot = len(incoming_slot.connection_slot)
        # Checks whether the connection has capped on its limit size.
        self.assertTrue(number_incoming_slot == max_incoming)

        # We repeat the analysis for all other slots.

        # --- outgoing slot ---

        out_peerList = []
        out_connList = []
        for i in range(0, max_outgoing):
            out_peerList.append(self.create_peer())
            out_connList.append(FakeConnection(out_peerList[i], full_node))
            self.simulator.add_connection(out_connList[i])

        self.simulator.run(10)

        outgoing_slot = full_node.connections.slots_manager.outgoing_slot
        number_outgoing_slot = len(outgoing_slot.connection_slot)

        self.assertTrue(number_outgoing_slot == max_outgoing)

        # --- bootstrap slot ---
        bootstrap_peerList = []
        bootstrap_connList = []
        for i in range(0, max_bootstrap):
            bootstrap_peerList.append(self.create_peer())
            bootstrap_connList.append(FakeConnection(bootstrap_peerList[i], full_node, fake_bootstrap_id=None))
            self.simulator.add_connection(bootstrap_connList[i])

        bootstrap_slot = full_node.connections.slots_manager.bootstrap_slot
        number_bootstrap_slot = len(bootstrap_slot.connection_slot)

        self.assertTrue(number_bootstrap_slot == max_bootstrap)

        # Finally, assure the number of connected peers is the same as the sum of all (no discovered connections).
        connection_pool = full_node.connections.connections
        self.assertTrue(number_outgoing_slot + number_incoming_slot + number_bootstrap_slot == len(connection_pool))
        self.assertTrue(len(connection_pool) <= max_connections)

    def test_wrong_conn_outgoing(self) -> None:
        """ Test if, by sending a connection to the wrong slot, it is blocked.
                Note: Connections stop being updated after removed from simulator."""

        full_node = self.create_peer()
        peer_in = self.create_peer()
        peer_boot = self.create_peer()

        # -> Test outgoing slot - make incoming and bootstrap connections.
        in_conn = FakeConnection(full_node, peer_in)
        boot_conn = FakeConnection(peer_boot, full_node, fake_bootstrap_id=None)

        self.simulator.add_connection(in_conn)
        self.simulator.add_connection(boot_conn)
        self.simulator.run(5)

        # Outgoing slot must not update, others must.
        outgoing_slot = full_node.connections.slots_manager.outgoing_slot
        incoming_slot = full_node.connections.slots_manager.incoming_slot
        bootstrap_slot = full_node.connections.slots_manager.bootstrap_slot

        self.assertTrue(len(outgoing_slot.connection_slot) == 0)
        self.assertTrue(len(bootstrap_slot.connection_slot) == 1)
        self.assertTrue(len(incoming_slot.connection_slot) == 1)

    def test_wrong_conn_incoming(self) -> None:

        full_node = self.create_peer()
        peer_out = self.create_peer()
        peer_boot = self.create_peer()

        # <- Test incoming slot - make incoming and bootstrap connections.

        out_conn = FakeConnection(peer_out, full_node)
        boot_conn = FakeConnection(peer_boot, full_node, fake_bootstrap_id=None)

        self.simulator.add_connection(out_conn)
        self.simulator.add_connection(boot_conn)
        self.simulator.run(5)

        # Incoming slot must not update, others must.
        outgoing_slot = full_node.connections.slots_manager.outgoing_slot
        incoming_slot = full_node.connections.slots_manager.incoming_slot
        bootstrap_slot = full_node.connections.slots_manager.bootstrap_slot

        self.assertTrue(len(outgoing_slot.connection_slot) == 1)
        self.assertTrue(len(bootstrap_slot.connection_slot) == 1)
        self.assertTrue(len(incoming_slot.connection_slot) == 0)

    def test_wrong_conn_bootstrap(self) -> None:

        full_node = self.create_peer()
        peer_out = self.create_peer()
        peer_in = self.create_peer()

        # <- Test incoming slot - make incoming and bootstrap connections.

        out_conn = FakeConnection(peer_out, full_node)
        in_conn = FakeConnection(full_node, peer_in)

        self.simulator.add_connection(out_conn)
        self.simulator.add_connection(in_conn)
        self.simulator.run(5)

        # Bootstrap slot must not update, others must.
        outgoing_slot = full_node.connections.slots_manager.outgoing_slot
        incoming_slot = full_node.connections.slots_manager.incoming_slot
        bootstrap_slot = full_node.connections.slots_manager.bootstrap_slot

        self.assertTrue(len(outgoing_slot.connection_slot) == 1)
        self.assertTrue(len(bootstrap_slot.connection_slot) == 0)
        self.assertTrue(len(incoming_slot.connection_slot) == 1)

    def test_connections_equal_slots(self) -> None:
        """ Test if connections keep equal to the sum of connections in each slot."""
        full_node = self.create_peer()
        number_out = 8  # Random numbers
        number_in = 11
        number_boot = 9
        out_peer_list = []
        in_peer_list = []
        boot_peer_list = []

        # Create peer lists:
        for _ in range(number_out):
            out_peer_list.append(self.create_peer())
        for _ in range(number_in):
            in_peer_list.append(self.create_peer())
        for _ in range(number_boot):
            boot_peer_list.append(self.create_peer())

        # Create connections to the peers in the list:

        # Outgoing:
        out_conn_list = []
        for _, peer in enumerate(out_peer_list):
            out_conn_list.append(FakeConnection(peer, full_node))
            self.simulator.add_connection(out_conn_list[-1])
        # Incoming:
        in_conn_list = []
        for _, peer in enumerate(in_peer_list):
            in_conn_list.append(FakeConnection(full_node, peer))
            self.simulator.add_connection(in_conn_list[-1])

        # Bootstrap:
        boot_conn_list = []
        for _, peer in enumerate(boot_peer_list):
            boot_conn_list.append(FakeConnection(peer, full_node, fake_bootstrap_id=None))
            self.simulator.add_connection(boot_conn_list[-1])

        self.simulator.run(1)

        connections = full_node.connections.connections
        outgoing_slot = full_node.connections.slots_manager.outgoing_slot.connection_slot
        incoming_slot = full_node.connections.slots_manager.incoming_slot.connection_slot
        bootstrap_slot = full_node.connections.slots_manager.bootstrap_slot.connection_slot

        sum_of_slots = len(bootstrap_slot) + len(incoming_slot) + len(outgoing_slot)

        self.assertTrue(len(connections) == sum_of_slots)

    def test_remove_connection(self) -> None:
        """Test if removing connections from each slot properly decreases slot and pool sizes."""

        full_node = self.create_peer()

        # Create one connection per slot type
        out_peer = self.create_peer()
        in_peer = self.create_peer()
        boot_peer = self.create_peer()

        out_conn = FakeConnection(out_peer, full_node)
        in_conn = FakeConnection(full_node, in_peer)
        boot_conn = FakeConnection(boot_peer, full_node, fake_bootstrap_id=None)

        self.simulator.add_connection(out_conn)
        self.simulator.add_connection(in_conn)
        self.simulator.add_connection(boot_conn)
        self.simulator.run(5)

        # Make sure three connections we appended to the whole pool
        self.assertTrue(len(full_node.connections.connections) == 3)

        # Remove outgoing
        out_conn.disconnect(Failure(Exception('test disconnect')))
        self.simulator.remove_connection(out_conn)
        self.simulator.run(1)

        outgoing_slot = full_node.connections.slots_manager.outgoing_slot
        self.assertTrue(len(outgoing_slot.connection_slot) == 0)
        self.assertTrue(len(full_node.connections.connections) == 2)

        # Remove incoming
        in_conn.disconnect(Failure(Exception('test disconnect')))
        self.simulator.remove_connection(in_conn)
        self.simulator.run(1)

        incoming_slot = full_node.connections.slots_manager.incoming_slot
        self.assertTrue(len(incoming_slot.connection_slot) == 0)
        self.assertTrue(len(full_node.connections.connections) == 1)

        # Remove bootstrap
        boot_conn.disconnect(Failure(Exception('test disconnect')))
        self.simulator.remove_connection(boot_conn)
        self.simulator.run(1)

        bootstrap_slot = full_node.connections.slots_manager.bootstrap_slot
        self.assertTrue(len(bootstrap_slot.connection_slot) == 0)
        self.assertTrue(len(full_node.connections.connections) == 0)


class CheckEntrypointsTestCase(SimulatorTestCase):
    def test_add_connection(self) -> None:

        max_outgoing = 1
        max_incoming = 1
        max_bootstrap = 1
        max_check_ep = 5
        max_queue_ep = 100

        full_node = self.create_peer()

        sm_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap, max_check_ep, max_queue_ep)
        full_node.connections.slots_manager = SlotsManager(sm_settings)

        # We'll add two connections to outgoing slot.

        out_peer_1 = self.create_peer()
        out_peer_2 = self.create_peer()

        out_conn_1 = FakeConnection(out_peer_1, full_node)
        out_conn_2 = FakeConnection(out_peer_2, full_node)
        self.simulator.add_connection(out_conn_1)
        self.simulator.add_connection(out_conn_2)
        self.simulator.run(1)

        # Make sure the outgoing slot is still at ONE connection
        outgoing_slot = full_node.connections.slots_manager.outgoing_slot
        assert len(outgoing_slot) == max_outgoing

        # Make sure there is still ONE connection in the check ep Slot
        check_ep_slot = full_node.connections.slots_manager.check_ep_slot
        assert len(check_ep_slot) == 1

    def test_type_change(self) -> None:
        max_outgoing = 1
        max_incoming = 1
        max_bootstrap = 1
        max_check_ep = 5
        max_queue_ep = 100

        full_node = self.create_peer()

        sm_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap, max_check_ep, max_queue_ep)
        full_node.connections.slots_manager = SlotsManager(sm_settings)

        # We'll add two connections to outgoing slot.

        out_peer_1 = self.create_peer()
        out_peer_2 = self.create_peer()

        out_conn_1 = FakeConnection(out_peer_1, full_node)
        out_conn_2 = FakeConnection(out_peer_2, full_node)
        self.simulator.add_connection(out_conn_1)
        self.simulator.add_connection(out_conn_2)
        self.simulator.run(1)

        # Assure the typing of connections. We use proto2 as full node is in the 2nd position.
        assert out_conn_1.proto2.connection_type == ConnectionType.OUTGOING
        assert out_conn_2.proto2.connection_type == ConnectionType.CHECK_ENTRYPOINTS

    def test_remove_connection_checkEp_slot(self) -> None:

        max_outgoing = 1
        max_incoming = 1
        max_bootstrap = 1
        max_check_ep = 5
        max_queue_ep = 100

        full_node = self.create_peer()

        sm_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap, max_check_ep, max_queue_ep)
        full_node.connections.slots_manager = SlotsManager(sm_settings)

        # Add two connections to outgoing, one will be at check_entrypoints.
        out_peer_1 = self.create_peer()
        out_peer_2 = self.create_peer()

        out_conn_1 = FakeConnection(out_peer_1, full_node)
        out_conn_2 = FakeConnection(out_peer_2, full_node)
        self.simulator.add_connection(out_conn_1)
        self.simulator.add_connection(out_conn_2)
        self.simulator.run(1)

        # Make sure there is still ONE connection in the check ep Slot
        check_ep_slot = full_node.connections.slots_manager.check_ep_slot

        # out_conn_2 should be the connection in check_ep_slot.
        out_conn_2.disconnect(Failure(Exception('forced reconnection')))
        self.simulator.remove_connection(out_conn_2)
        self.simulator.run(1)

        assert len(check_ep_slot) == 0

    def test_multiple_check_ep_connections(self) -> None:
        """Attempt lots of connections towards check_entrypoints, see if it caps."""
        max_outgoing = 1
        max_incoming = 1
        max_bootstrap = 1
        max_check_ep = 5
        max_queue_ep = 100

        full_node = self.create_peer()

        sm_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap, max_check_ep, max_queue_ep)
        full_node.connections.slots_manager = SlotsManager(sm_settings)
        check_ep_slot = full_node.connections.slots_manager.check_ep_slot

        # Now, we add multiple connections to check_ep_slot and see if it caps.
        for _ in range(max_check_ep + 5):
            out_peer = self.create_peer()
            out_conn = FakeConnection(out_peer, full_node)
            self.simulator.add_connection(out_conn)

        self.simulator.run(1)

        assert check_ep_slot.is_slot_full()
        assert len(check_ep_slot) == max_check_ep

    def test_queue_after_slot_filling(self) -> None:
        """We'll keep track of the number of entrypoints in the queue and make sure none is lost."""
        max_outgoing = 1
        max_incoming = 1
        max_bootstrap = 1
        max_check_ep = 5
        max_queue_ep = 10000

        n_in_queue = 5  # Number of entrypoints we wish to see in queue.

        full_node = self.create_peer()
        sm_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap, max_check_ep, max_queue_ep)
        full_node.connections.slots_manager = SlotsManager(sm_settings)
        check_ep_slot = full_node.connections.slots_manager.check_ep_slot

        # Now, we add multiple connections to check_ep_slot and see if it caps.
        for _ in range(max_check_ep + max_outgoing + n_in_queue):
            out_peer = self.create_peer()
            out_conn = FakeConnection(out_peer, full_node)
            self.simulator.add_connection(out_conn)

        self.simulator.run(1)

        # Make sure slot caps at the expected size
        assert len(check_ep_slot) == max_check_ep

        # Now, let us see if the queue stores the correct number of entrypoints in the queue
        if n_in_queue > max_queue_ep:
            n_in_queue = max_queue_ep

        assert len(check_ep_slot.entrypoint_queue) == n_in_queue

    def test_queue_cap(self) -> None:
        """Test if the queue does limit the amount of allowed entrypoints. """
        max_outgoing = 1
        max_incoming = 1
        max_bootstrap = 1
        max_check_ep = 5
        max_queue_ep = 10

        n_ep_voided = 5  # Number of entrypoints we wish to see out of queue

        # Code n to be out of the queue's limit
        n_to_queue = max_queue_ep + n_ep_voided

        full_node = self.create_peer()

        sm_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap, max_check_ep, max_queue_ep)
        full_node.connections.slots_manager = SlotsManager(sm_settings)
        check_ep_slot = full_node.connections.slots_manager.check_ep_slot

        # Now, we add multiple connections to check_ep_slot and see if it caps.
        for _ in range(max_outgoing + n_to_queue):
            out_peer = self.create_peer()
            out_conn = FakeConnection(out_peer, full_node)
            self.simulator.add_connection(out_conn)

        self.simulator.run(1)

        # Now, let us see if the queue stores the correct number of entrypoints in the queue
        assert len(check_ep_slot.entrypoint_queue) == max_queue_ep

    def test_entrypoint_queue_removal(self) -> None:
        """Test the """
        max_outgoing = 1
        max_incoming = 1
        max_bootstrap = 1
        max_check_ep = 5
        max_queue_ep = 10
        extra_eps = 3
        full_node = self.create_peer()

        sm_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap, max_check_ep, max_queue_ep)
        full_node.connections.slots_manager = SlotsManager(sm_settings)
        check_ep_slot = full_node.connections.slots_manager.check_ep_slot

        out_conn_list: list[FakeConnection] = []
        check_conn_list: list[FakeConnection] = []

        # We'll add some connections but we'll leave space in the queue.
        for _ in range(max_outgoing):
            out_peer = self.create_peer()
            out_conn = FakeConnection(out_peer, full_node)
            out_conn_list.append(out_conn)
            self.simulator.add_connection(out_conn)

        for _ in range(max_check_ep):
            check_peer = self.create_peer()
            check_conn = FakeConnection(check_peer, full_node)
            check_conn_list.append(check_conn)
            self.simulator.add_connection(check_conn)

        # We'll manually add the entrypoints, since proto2 does not set up correctly entrypoints.
        from hathor.p2p.peer_endpoint import PeerAddress
        known_entrypoints = []
        for _ in range(extra_eps):
            peer = self.create_peer()
            ep = PeerAddress.from_address(
                IPv4Address('TCP', '127.0.0.1', FakeConnection._get_port(peer))
            ).with_id(peer.my_peer.id)
            known_entrypoints.append(ep.addr)
            check_ep_slot.put_on_queue(ep)

        self.simulator.run(1)

        # Let us see if the queue stores the correct number of entrypoints in the queue
        assert len(check_ep_slot.entrypoint_queue) == extra_eps
        assert len(check_ep_slot.dequeued_entrypoints) == 0

        # Now, we'll remove a connection, and see if the entrypoint is appended.
        check_conn = check_conn_list[-1]

        # Mocking parameters for should_blacklist
        check_conn.proto2.diff_timestamp = 10
        check_conn.proto2.idle_timeout = 100

        check_conn.disconnect(Failure(Exception('forced reconnection')))
        self.simulator.remove_connection(check_conn)

        # Run the simulator and see if the entrypoint has been updated.
        self.simulator.run(1)

        # Check if the entrypoint has been dequeued.
        assert len(check_ep_slot) == max_check_ep - 1
        assert len(check_ep_slot.entrypoint_queue) == extra_eps - 1
        assert len(check_ep_slot.dequeued_entrypoints) == 1

        # We'll now MOCK the connect_to_endpoint by reconnecting the call manually.
        # The queue is FIFO:
        dequeued_addr = next(iter(check_ep_slot.dequeued_entrypoints))
        assert dequeued_addr == known_entrypoints[0]

        # Build a protocol manually with the dequeued entrypoint pre-set,
        # then call add_to_slot. This bypasses connect_to_endpoint (which
        # doesn't work in the simulator) but exercises the real slot logic.
        rebound_addr = IPv4Address('TCP', '127.0.0.1', 59999)
        proto_rebound = full_node.connections.client_factory.buildProtocol(rebound_addr)
        proto_rebound.entrypoint = dequeued_addr.with_id(None)

        # add_to_slot sees entrypoint in dequeued_entrypoints and reclassifies to REBOUNDED
        full_node.connections.slots_manager.add_to_slot(proto_rebound)
        self.simulator.run(5)

        # Therefore:
        # 1. The slots manager put it to CheckEntrypoints Slot
        # 2. In the slot, ep is in dequeued, so type changes to REBOUNDED
        # 3. The protocol is stored in the rebounded slot, with the ep from dequeue.

        # Hence, dequeueing mechanism seems to be working.
        assert proto_rebound.connection_type == ConnectionType.REBOUNDED
        assert check_ep_slot.rebound_slot == proto_rebound
        assert proto_rebound.entrypoint.addr == dequeued_addr

    def test_remove_when_queue_full(self) -> None:
        """When a READY check_ep protocol is removed and its peer's entrypoints should be
        queued, but the queue is already full, the overflow entrypoints are silently dropped."""
        max_outgoing = 1
        max_incoming = 1
        max_bootstrap = 1
        max_check_ep = 5
        max_queue_ep = 2  # Small queue so we can fill it easily.
        full_node = self.create_peer()

        sm_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap, max_check_ep, max_queue_ep)
        full_node.connections.slots_manager = SlotsManager(sm_settings)
        check_ep_slot = full_node.connections.slots_manager.check_ep_slot

        # Fill outgoing slot.
        out_peer = self.create_peer()
        out_conn = FakeConnection(out_peer, full_node)
        self.simulator.add_connection(out_conn)

        # Overflow to check_ep_slot.
        check_peer = self.create_peer()
        check_conn = FakeConnection(check_peer, full_node, fresh_entrypoints=True)
        self.simulator.add_connection(check_conn)
        self.simulator.run(1)

        assert len(check_ep_slot) == 1

        # Fill the queue to max before removing the protocol.
        from hathor.p2p.peer_endpoint import PeerAddress
        for i in range(max_queue_ep):
            filler_ep = PeerAddress.from_address(
                IPv4Address('TCP', '127.0.0.1', 61000 + i)
            ).with_id(full_node.my_peer.id)
            check_ep_slot.put_on_queue(filler_ep)

        assert check_ep_slot.is_queue_full()

        # Inject extra entrypoints into the peer's info.
        extra_ep_1 = PeerAddress.from_address(
            IPv4Address('TCP', '127.0.0.1', 60001)
        ).with_id(check_peer.my_peer.id)
        extra_ep_2 = PeerAddress.from_address(
            IPv4Address('TCP', '127.0.0.1', 60002)
        ).with_id(check_peer.my_peer.id)

        check_conn.proto2.peer.info.entrypoints.add(extra_ep_1.addr)
        check_conn.proto2.peer.info.entrypoints.add(extra_ep_2.addr)

        # Force READY so removal triggers the entrypoint-fetching path.
        check_conn.proto2.connection_state = ConnectionState.READY
        check_conn.proto2.diff_timestamp = 10
        check_conn.proto2.idle_timeout = 100

        # Disconnect — unseen + READY, so it tries to queue peer entrypoints, but queue is full.
        # Note: remove_connection also triggers kickstart (pops one filler from the queue).
        check_conn.disconnect(Failure(Exception('done checking')))
        self.simulator.remove_connection(check_conn)
        self.simulator.run(1)

        # Kickstart popped one filler, so queue is max_queue_ep - 1.
        # The extra entrypoints were NOT added because the queue was full at the time of the attempt.
        assert len(check_ep_slot.entrypoint_queue) == max_queue_ep - 1
        assert len(check_ep_slot.dequeued_entrypoints) == 1

        # The extra entrypoints must NOT have made it into the queue.
        queued_addrs = set(ep.addr for ep in check_ep_slot.entrypoint_queue)
        assert extra_ep_1.addr not in queued_addrs
        assert extra_ep_2.addr not in queued_addrs

    def test_fetch_entrypoints_from_ready_protocol(self) -> None:
        """Test that when a check_ep protocol becomes READY and is removed,
      its peer's other entrypoints get queued."""
        max_outgoing = 1
        max_incoming = 1
        max_bootstrap = 1
        max_check_ep = 5
        max_queue_ep = 100

        full_node = self.create_peer()
        sm_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap, max_check_ep, max_queue_ep)
        full_node.connections.slots_manager = SlotsManager(sm_settings)
        check_ep_slot = full_node.connections.slots_manager.check_ep_slot

        # First connection fills outgoing
        out_peer = self.create_peer()
        out_conn = FakeConnection(out_peer, full_node)
        self.simulator.add_connection(out_conn)

        # Second connection overflows to check_ep, with fresh_entrypoints so it gets one
        check_peer = self.create_peer()
        check_conn = FakeConnection(check_peer, full_node, fresh_entrypoints=True)
        self.simulator.add_connection(check_conn)
        self.simulator.run(1)

        assert len(check_ep_slot) == 1
        assert check_conn.proto2.connection_type == ConnectionType.CHECK_ENTRYPOINTS

        # Manually inject additional entrypoints into the peer's info, simulating
        # entrypoints that the peer advertised.
        from hathor.p2p.peer_endpoint import PeerAddress
        extra_ep_1 = PeerAddress.from_address(
            IPv4Address('TCP', '127.0.0.1', 60001)
        ).with_id(check_peer.my_peer.id)
        extra_ep_2 = PeerAddress.from_address(
            IPv4Address('TCP', '127.0.0.1', 60002)
        ).with_id(check_peer.my_peer.id)

        # Add entrypoints to the peer info so remove_connection can read them
        check_conn.proto2.peer.info.entrypoints.add(extra_ep_1.addr)
        check_conn.proto2.peer.info.entrypoints.add(extra_ep_2.addr)

        # Force the protocol to READY state so the removal path fetches entrypoints
        check_conn.proto2.connection_state = ConnectionState.READY

        # Now remove it — since entrypoint was unseen, peer's entrypoints should be queued
        check_conn.proto2.diff_timestamp = 10
        check_conn.proto2.idle_timeout = 100

        check_conn.disconnect(Failure(Exception('done checking')))
        self.simulator.remove_connection(check_conn)
        self.simulator.run(1)

        # The two extra entrypoints should be in the queue (the main one was already seen)

        # EVENTUALLY: CHANGE ENTRYPOINT QUEUE TO BE PEER ADDRESS ALSO, LIKE THE REST.
        # Change everything.
        assert len(check_ep_slot.entrypoint_queue) + len(check_ep_slot.dequeued_entrypoints) >= 2
        queued_addrs = set(ep.addr for ep in check_ep_slot.entrypoint_queue)
        dequeued_addrs = set(ep_addr for ep_addr in check_ep_slot.dequeued_entrypoints)
        assert extra_ep_1.addr in dequeued_addrs or extra_ep_1.addr in queued_addrs
        assert extra_ep_2.addr in queued_addrs or extra_ep_2.addr in dequeued_addrs

    def test_ep_requeue_for_busy_rebound_slot(self) -> None:
        """When a REBOUNDED protocol arrives but the rebound_slot is already occupied,
        its entrypoint must be put back on the queue and the connection rejected."""
        max_outgoing = 1
        max_incoming = 1
        max_bootstrap = 1
        max_check_ep = 5
        max_queue_ep = 100
        full_node = self.create_peer()

        sm_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap, max_check_ep, max_queue_ep)
        full_node.connections.slots_manager = SlotsManager(sm_settings)
        check_ep_slot = full_node.connections.slots_manager.check_ep_slot

        # Fill the outgoing slot.
        out_peer = self.create_peer()
        out_conn = FakeConnection(out_peer, full_node)
        self.simulator.add_connection(out_conn)

        # Fill check_ep_slot with max_check_ep connections so the queue gets entries.
        check_conn_list: list[FakeConnection] = []
        for _ in range(max_check_ep):
            peer = self.create_peer()
            conn = FakeConnection(peer, full_node)
            check_conn_list.append(conn)
            self.simulator.add_connection(conn)

        self.simulator.run(1)
        assert len(check_ep_slot) == max_check_ep

        # Manually queue two entrypoints so we can dequeue them later.
        from hathor.p2p.peer_endpoint import PeerAddress
        ep_a = PeerAddress.from_address(
            IPv4Address('TCP', '127.0.0.1', 60101)
        ).with_id(full_node.my_peer.id)
        ep_b = PeerAddress.from_address(
            IPv4Address('TCP', '127.0.0.1', 60102)
        ).with_id(full_node.my_peer.id)

        check_ep_slot.put_on_queue(ep_a)
        check_ep_slot.put_on_queue(ep_b)
        assert len(check_ep_slot.entrypoint_queue) == 2

        # Pop ep_a from queue (FIFO: ep_a was pushed first via appendleft, but ep_b was pushed
        # after, so ep_a is on the right). This marks ep_a.addr in dequeued_entrypoints.
        popped = check_ep_slot.pop_from_queue()
        assert popped is not None
        assert popped.addr in check_ep_slot.dequeued_entrypoints
        # Place a protocol in rebound_slot to occupy it.
        rebound_addr_1 = IPv4Address('TCP', '127.0.0.1', 59801)
        proto_rebound_1 = full_node.connections.client_factory.buildProtocol(rebound_addr_1)
        proto_rebound_1.entrypoint = popped
        proto_rebound_1.connection_type = ConnectionType.REBOUNDED
        # Directly place in rebound_slot (bypassing add_connection for setup).
        check_ep_slot.rebound_slot = proto_rebound_1

        assert check_ep_slot.rebound_slot is not None

        # Pop ep_b from queue and mark it as dequeued.
        popped_b = check_ep_slot.pop_from_queue()
        assert popped_b is not None
        assert popped_b.addr in check_ep_slot.dequeued_entrypoints
        popped_b_addr = popped_b.addr

        # Queue should now be empty.
        assert len(check_ep_slot.entrypoint_queue) == 0

        # Build a second REBOUNDED protocol for ep_b — rebound_slot is busy.
        rebound_addr_2 = IPv4Address('TCP', '127.0.0.1', 59802)
        proto_rebound_2 = full_node.connections.client_factory.buildProtocol(rebound_addr_2)
        proto_rebound_2.entrypoint = popped_b
        proto_rebound_2.connection_type = ConnectionType.REBOUNDED

        # Attempt to add — should be rejected because rebound_slot is occupied.
        result = check_ep_slot.add_connection(proto_rebound_2)

        from hathor.p2p.connection_slot import ConnectionRejected
        assert isinstance(result, ConnectionRejected)

        # The entrypoint must have been put back on the queue.
        assert len(check_ep_slot.entrypoint_queue) == 1
        requeued_ep = check_ep_slot.entrypoint_queue[0]
        assert requeued_ep.addr == popped_b_addr

        # rebound_slot must still hold the first protocol.
        assert check_ep_slot.rebound_slot is proto_rebound_1

    def test_blacklist_blocking(self) -> None:
        "We'll test if, when attempting to connect to a blacklisted peer, protocol is blocked. "
        max_outgoing = 1
        max_incoming = 1
        max_bootstrap = 1
        max_check_ep = 5
        max_queue_ep = 10
        full_node = self.create_peer()

        sm_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap, max_check_ep, max_queue_ep)
        full_node.connections.slots_manager = SlotsManager(sm_settings)
        check_ep_slot = full_node.connections.slots_manager.check_ep_slot

        # We'll make a connection timeout, without being ready.

        # First connection (outgoing slot)
        out_peer_1 = self.create_peer()
        out_conn_1 = FakeConnection(out_peer_1, full_node)
        self.simulator.add_connection(out_conn_1)

        # Second connection (check_ep_slot) - we'll set entrypoints to be avaiable from the beginning.
        out_peer_2 = self.create_peer()
        out_conn_2 = FakeConnection(out_peer_2, full_node, fresh_entrypoints=True)
        self.simulator.add_connection(out_conn_2)

        # Run the simulator
        self.simulator.run(1)

        # Assert the shift
        assert len(check_ep_slot) == 1

        # We'll force the connection to be blacklisted.
        # For this, we'll:
        # 1. Force the connection to revert back to CONNECTING... State.
        # 2. Give timeout burst parameters.

        # The entrypoint which we'll ban.
        banned_entrypoint = out_conn_2.entrypoint
        assert banned_entrypoint is not None

        # We'll alter the params on the fly before disconnection to trigger blacklisting.
        out_conn_2.proto1.entrypoint = banned_entrypoint
        out_conn_2.proto1.idle_timeout = 1
        out_conn_2.proto1.diff_timestamp = 1
        out_conn_2.proto1.connection_state = ConnectionState.CONNECTING
        out_conn_2.proto2.entrypoint = banned_entrypoint
        out_conn_2.proto2.idle_timeout = 1
        out_conn_2.proto2.diff_timestamp = 1
        out_conn_2.proto2.connection_state = ConnectionState.CONNECTING

        # Remove connection - at this point, blacklist must be triggered.
        out_conn_2.disconnect(Failure(Exception('Forced disconnection')))
        self.simulator.remove_connection(out_conn_2)

        # Run the simulator
        self.simulator.run(1)

        # Assert that the connection is gone from slot.
        assert len(check_ep_slot) == 0

        # Assert that the entrypoint has been banned:
        assert full_node.connections.slots_manager.is_blacklisted(banned_entrypoint)

        # Build a new connection, then disconnect it, blacklist its entrypoint, and reconnect.
        new_peer = self.create_peer()
        new_conn = FakeConnection(new_peer, full_node, fresh_entrypoints=True)
        self.simulator.add_connection(new_conn)
        self.simulator.run(1)

        # The new connection entered check_ep_slot (outgoing was full).
        assert len(check_ep_slot) == 1

        # Now blacklist the actual entrypoint address and disconnect.
        blacklisted_addr = new_conn.proto2.entrypoint.addr
        new_conn.disconnect(Failure(Exception('forced disconnection')))
        self.simulator.remove_connection(new_conn)
        self.simulator.run(1)
        assert len(check_ep_slot) == 0

        full_node.connections.slots_manager.blacklisted_entrypoints.entrypoint_set.add(blacklisted_addr)

        # Reconnect — the blacklist gate in on_peer_connect should now block it.
        new_conn.reconnect()
        self.simulator.add_connection(new_conn)
        self.simulator.run(1)

        # The connection should have been rejected by the blacklist check.
        assert len(check_ep_slot) == 0

    def test_time_map_and_stamps(self) -> None:
        pass

    def test_attempt_delisting_before_expiration(self) -> None:
        """Attempt to delist an entrypoint before time penalty.
        Blacklist an entrypoint, advance the clock by less than TIME_PENALTY,
        then try to reconnect with the same entrypoint. The connection must be rejected."""
        max_outgoing = 1
        max_incoming = 1
        max_bootstrap = 1
        max_check_ep = 5
        max_queue_ep = 10
        full_node = self.create_peer()

        sm_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap, max_check_ep, max_queue_ep)
        full_node.connections.slots_manager = SlotsManager(sm_settings)
        check_ep_slot = full_node.connections.slots_manager.check_ep_slot
        blacklisted_set = full_node.connections.slots_manager.blacklisted_entrypoints

        # First connection fills outgoing slot.
        out_peer = self.create_peer()
        out_conn = FakeConnection(out_peer, full_node)
        self.simulator.add_connection(out_conn)

        # Second connection overflows to check_ep_slot.
        check_peer = self.create_peer()
        check_conn = FakeConnection(check_peer, full_node, fresh_entrypoints=True)
        self.simulator.add_connection(check_conn)
        self.simulator.run(1)

        assert len(check_ep_slot) == 1

        # Record the entrypoint we'll blacklist.
        banned_entrypoint = check_conn.entrypoint
        assert banned_entrypoint is not None
        banned_addr = banned_entrypoint.addr

        # Force blacklist conditions: not READY, timed out.
        check_conn.proto2.entrypoint = banned_entrypoint
        check_conn.proto2.idle_timeout = 1
        check_conn.proto2.diff_timestamp = 1
        check_conn.proto2.connection_state = ConnectionState.CONNECTING

        # Disconnect — triggers blacklisting.
        check_conn.disconnect(Failure(Exception('forced timeout')))
        self.simulator.remove_connection(check_conn)
        self.simulator.run(1)

        # Confirm blacklisted.
        assert full_node.connections.slots_manager.is_blacklisted(banned_entrypoint)
        assert banned_addr in blacklisted_set.entrypoint_set
        assert banned_addr in blacklisted_set.time_map

        # Advance clock by LESS than TIME_PENALTY (600s). Use 300s (half).
        self.simulator._clock.advance(300)

        # Reconnect the same FakeConnection — it carries the same (banned) entrypoint.
        check_conn.reconnect()
        self.simulator.add_connection(check_conn)
        self.simulator.run(1)

        # The connection must have been rejected — blacklist not expired.
        assert len(check_ep_slot) == 0

        # Entrypoint must still be blacklisted.
        assert banned_addr in blacklisted_set.entrypoint_set
        assert banned_addr in blacklisted_set.time_map

    def test_attempt_delisting_after_expiration(self) -> None:
        """Attempt to delist after penalty, and attempt new connection to see its
        protocol not being blocked."""
        max_outgoing = 1
        max_incoming = 1
        max_bootstrap = 1
        max_check_ep = 5
        max_queue_ep = 10
        full_node = self.create_peer()

        sm_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap, max_check_ep, max_queue_ep)
        full_node.connections.slots_manager = SlotsManager(sm_settings)
        check_ep_slot = full_node.connections.slots_manager.check_ep_slot
        blacklisted_set = full_node.connections.slots_manager.blacklisted_entrypoints

        # First connection fills outgoing slot.
        out_peer = self.create_peer()
        out_conn = FakeConnection(out_peer, full_node)
        self.simulator.add_connection(out_conn)

        # Second connection overflows to check_ep_slot.
        check_peer = self.create_peer()
        check_conn = FakeConnection(check_peer, full_node, fresh_entrypoints=True)
        self.simulator.add_connection(check_conn)
        self.simulator.run(1)

        assert len(check_ep_slot) == 1

        # Record the entrypoint we'll blacklist.
        banned_entrypoint = check_conn.entrypoint
        assert banned_entrypoint is not None
        banned_addr = banned_entrypoint.addr

        # Force blacklist conditions: not READY, timed out.
        check_conn.proto2.entrypoint = banned_entrypoint
        check_conn.proto2.idle_timeout = 1
        check_conn.proto2.diff_timestamp = 1
        check_conn.proto2.connection_state = ConnectionState.CONNECTING

        # Disconnect — triggers blacklisting.
        check_conn.disconnect(Failure(Exception('forced timeout')))
        self.simulator.remove_connection(check_conn)
        self.simulator.run(1)

        # Confirm blacklisted.
        assert full_node.connections.slots_manager.is_blacklisted(banned_entrypoint)
        assert banned_addr in blacklisted_set.entrypoint_set
        assert banned_addr in blacklisted_set.time_map

        # Advance clock PAST TIME_PENALTY (600s). Use 601s.
        self.simulator._clock.advance(601)

        # Reconnect the same FakeConnection — it carries the same (banned) entrypoint.
        check_conn.reconnect()
        self.simulator.add_connection(check_conn)
        self.simulator.run(1)

        # The connection must have been accepted — blacklist expired.
        # on_peer_connect calls may_unblacklist -> True, then remove_from_blacklist.
        assert len(check_ep_slot) == 1

        # Entrypoint must have been removed from the blacklist.
        assert banned_addr not in blacklisted_set.entrypoint_set
        assert banned_addr not in blacklisted_set.time_map

    def test_rebound_full_queue(self) -> None:
        """Test the rebound mechanism, and see if it voids the entrypoint
        when the queue, where it is supposed to go, is full."""
        max_outgoing = 1
        max_incoming = 1
        max_bootstrap = 1
        max_check_ep = 5
        max_queue_ep = 3  # Small queue so we can fill it easily.
        full_node = self.create_peer()

        sm_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap, max_check_ep, max_queue_ep)
        full_node.connections.slots_manager = SlotsManager(sm_settings)
        check_ep_slot = full_node.connections.slots_manager.check_ep_slot

        # Fill the outgoing slot.
        out_peer = self.create_peer()
        out_conn = FakeConnection(out_peer, full_node)
        self.simulator.add_connection(out_conn)

        # Fill check_ep_slot so we can work with the queue directly.
        check_conn_list: list[FakeConnection] = []
        for _ in range(max_check_ep):
            peer = self.create_peer()
            conn = FakeConnection(peer, full_node)
            check_conn_list.append(conn)
            self.simulator.add_connection(conn)

        self.simulator.run(1)
        assert len(check_ep_slot) == max_check_ep

        # Manually queue entrypoints to fill the queue completely.
        from hathor.p2p.peer_endpoint import PeerAddress
        for i in range(max_queue_ep):
            ep = PeerAddress.from_address(
                IPv4Address('TCP', '127.0.0.1', 61000 + i)
            ).with_id(full_node.my_peer.id)
            check_ep_slot.put_on_queue(ep)

        assert check_ep_slot.is_queue_full()

        # Pop one entrypoint to create a REBOUNDED protocol for it.
        popped_a = check_ep_slot.pop_from_queue()
        assert popped_a is not None

        # Re-fill the queue back to max.
        refill_ep = PeerAddress.from_address(
            IPv4Address('TCP', '127.0.0.1', 62000)
        ).with_id(full_node.my_peer.id)
        check_ep_slot.put_on_queue(refill_ep)
        assert check_ep_slot.is_queue_full()

        # Occupy rebound_slot with a protocol for popped_a.
        occupy_addr = IPv4Address('TCP', '127.0.0.1', 59701)
        proto_occupy = full_node.connections.client_factory.buildProtocol(occupy_addr)
        proto_occupy.entrypoint = popped_a
        proto_occupy.connection_type = ConnectionType.REBOUNDED
        check_ep_slot.rebound_slot = proto_occupy

        # Pop another entrypoint — this one will be the dropped victim.
        popped_b = check_ep_slot.pop_from_queue()
        assert popped_b is not None

        # Re-fill the queue again so the put_on_queue inside add_connection will fail.
        refill_ep_2 = PeerAddress.from_address(
            IPv4Address('TCP', '127.0.0.1', 62001)
        ).with_id(full_node.my_peer.id)
        check_ep_slot.put_on_queue(refill_ep_2)
        assert check_ep_slot.is_queue_full()
        queue_snapshot = list(check_ep_slot.entrypoint_queue)

        # Build a REBOUNDED protocol for popped_b — rebound occupied AND queue full.
        reject_addr = IPv4Address('TCP', '127.0.0.1', 59702)
        proto_rejected = full_node.connections.client_factory.buildProtocol(reject_addr)
        proto_rejected.entrypoint = popped_b
        proto_rejected.connection_type = ConnectionType.REBOUNDED

        result = check_ep_slot.add_connection(proto_rejected)

        from hathor.p2p.connection_slot import ConnectionRejected
        assert isinstance(result, ConnectionRejected)

        # Queue must still be full — the entrypoint was dropped, not re-added.
        assert check_ep_slot.is_queue_full()
        assert len(check_ep_slot.entrypoint_queue) == max_queue_ep

        # Queue contents unchanged — dropped entrypoint did not squeeze in.
        assert list(check_ep_slot.entrypoint_queue) == queue_snapshot

        # rebound_slot still holds the first protocol.
        assert check_ep_slot.rebound_slot is proto_occupy

    def test_E2E_full_life_cycle(self) -> None:
        """End-to-end test of the CheckEntrypoints mechanism.

        Three protocols:
        - peer_A: times out → blacklisted → unblacklisted after TIME_PENALTY → reconnects → READY
        - peer_B: reaches READY → disconnected → extra entrypoints queued → rebound chain drains them
        - peer_C: has an already-seen entrypoint → reaches READY → peer entrypoints NOT re-fetched
        """
        from hathor.p2p.peer_endpoint import PeerAddress

        max_outgoing = 1
        max_incoming = 1
        max_bootstrap = 1
        max_check_ep = 2
        max_queue_ep = 100
        full_node = self.create_peer()

        sm_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap, max_check_ep, max_queue_ep)
        full_node.connections.slots_manager = SlotsManager(sm_settings)
        check_ep_slot = full_node.connections.slots_manager.check_ep_slot
        blacklisted_set = full_node.connections.slots_manager.blacklisted_entrypoints

        # --- Phase 1: Fill outgoing slot ---
        peer_out = self.create_peer()
        out_conn = FakeConnection(peer_out, full_node)
        self.simulator.add_connection(out_conn)
        self.simulator.run(1)

        outgoing_slot = full_node.connections.slots_manager.outgoing_slot
        assert len(outgoing_slot) == 1
        assert len(check_ep_slot) == 0

        # --- Phase 2: peer_A overflows to check_ep, times out, gets blacklisted ---
        peer_A = self.create_peer()
        conn_A = FakeConnection(peer_A, full_node, fresh_entrypoints=True)
        self.simulator.add_connection(conn_A)
        self.simulator.run(1)

        assert conn_A.proto2.connection_type == ConnectionType.CHECK_ENTRYPOINTS
        assert len(check_ep_slot) == 1

        # Record entrypoint before forcing timeout.
        ep_A = conn_A.entrypoint
        assert ep_A is not None
        addr_A = ep_A.addr

        # Force timeout conditions: not READY, diff_timestamp >= idle_timeout.
        conn_A.proto2.entrypoint = ep_A
        conn_A.proto2.idle_timeout = 1
        conn_A.proto2.diff_timestamp = 1
        conn_A.proto2.connection_state = ConnectionState.CONNECTING

        # Disconnect — triggers blacklisting.
        conn_A.disconnect(Failure(Exception('peer_A timeout')))
        self.simulator.remove_connection(conn_A)
        self.simulator.run(1)

        assert len(check_ep_slot) == 0
        assert full_node.connections.slots_manager.is_blacklisted(ep_A)
        assert addr_A in blacklisted_set.entrypoint_set
        assert addr_A in blacklisted_set.time_map

        # --- Phase 3: peer_B reaches READY, extra entrypoints queued ---
        peer_B = self.create_peer()
        conn_B = FakeConnection(peer_B, full_node, fresh_entrypoints=True)
        self.simulator.add_connection(conn_B)
        self.simulator.run(1)

        assert conn_B.proto2.connection_type == ConnectionType.CHECK_ENTRYPOINTS
        assert len(check_ep_slot) == 1

        # Inject extra entrypoints into peer_B's info, simulating advertised entrypoints.
        extra_ep_1 = PeerAddress.from_address(
            IPv4Address('TCP', '127.0.0.1', 60001)
        ).with_id(peer_B.my_peer.id)
        extra_ep_2 = PeerAddress.from_address(
            IPv4Address('TCP', '127.0.0.1', 60002)
        ).with_id(peer_B.my_peer.id)

        conn_B.proto2.peer.info.entrypoints.add(extra_ep_1.addr)
        conn_B.proto2.peer.info.entrypoints.add(extra_ep_2.addr)

        # Force READY state so removal fetches peer entrypoints.
        conn_B.proto2.connection_state = ConnectionState.READY
        conn_B.proto2.diff_timestamp = 10
        conn_B.proto2.idle_timeout = 100

        # Disconnect — since entrypoint was unseen and READY, peer's extra entrypoints get queued.
        conn_B.disconnect(Failure(Exception('peer_B checked')))
        self.simulator.remove_connection(conn_B)
        self.simulator.run(1)

        assert len(check_ep_slot) == 0

        # extra_ep_1 and extra_ep_2 should be queued or dequeued (kickstart pops one immediately).
        queued_addrs = set(ep.addr for ep in check_ep_slot.entrypoint_queue)
        dequeued_addrs = check_ep_slot.dequeued_entrypoints
        assert extra_ep_1.addr in queued_addrs or extra_ep_1.addr in dequeued_addrs
        assert extra_ep_2.addr in queued_addrs or extra_ep_2.addr in dequeued_addrs

        # Both should now be in seen_entrypoints.
        assert extra_ep_1.addr in check_ep_slot.seen_entrypoints
        assert extra_ep_2.addr in check_ep_slot.seen_entrypoints

        # --- Phase 4: Rebound chain drains dequeued entrypoints ---
        # Kickstart should have popped one entrypoint already. Identify it.
        assert len(check_ep_slot.dequeued_entrypoints) == 1
        dequeued_addr_1 = next(iter(check_ep_slot.dequeued_entrypoints))

        # Build a protocol for the dequeued entrypoint, simulating connect_to_endpoint callback.
        rebound_addr_1 = IPv4Address('TCP', '127.0.0.1', 59801)
        proto_rebound_1 = full_node.connections.client_factory.buildProtocol(rebound_addr_1)
        proto_rebound_1.entrypoint = dequeued_addr_1.with_id(peer_B.my_peer.id)

        # add_to_slot sees entrypoint in dequeued_entrypoints → reclassifies to REBOUNDED.
        full_node.connections.slots_manager.add_to_slot(proto_rebound_1)

        assert proto_rebound_1.connection_type == ConnectionType.REBOUNDED
        assert check_ep_slot.rebound_slot is proto_rebound_1

        # Safe timeout so it won't blacklist (diff_timestamp < idle_timeout).
        # Not READY: manually-built protocols have no peer, so we avoid the fetch-entrypoints path.
        proto_rebound_1.diff_timestamp = 10
        proto_rebound_1.idle_timeout = 100

        # Remove from slot — triggers usual_flow dequeue of the second entrypoint.
        removal_result = check_ep_slot.remove_connection(proto_rebound_1)

        assert check_ep_slot.rebound_slot is None
        assert removal_result.entrypoint is not None

        # The second extra_ep should now be dequeued.
        assert len(check_ep_slot.dequeued_entrypoints) == 2
        assert len(check_ep_slot.entrypoint_queue) == 0

        # --- Phase 5: peer_C has an already-seen entrypoint, entrypoints NOT re-fetched ---
        # The second dequeued entrypoint is already in seen_entrypoints from Phase 3.
        dequeued_addr_2 = removal_result.entrypoint.addr
        assert dequeued_addr_2 in check_ep_slot.seen_entrypoints

        # Build a protocol for it, simulating connect_to_endpoint callback.
        rebound_addr_2 = IPv4Address('TCP', '127.0.0.1', 59802)
        proto_C = full_node.connections.client_factory.buildProtocol(rebound_addr_2)
        proto_C.entrypoint = dequeued_addr_2.with_id(peer_B.my_peer.id)

        full_node.connections.slots_manager.add_to_slot(proto_C)

        assert proto_C.connection_type == ConnectionType.REBOUNDED
        assert check_ep_slot.rebound_slot is proto_C

        # Safe timeout so it won't blacklist (diff_timestamp < idle_timeout).
        # Not READY: manually-built protocols have no peer.
        proto_C.diff_timestamp = 10
        proto_C.idle_timeout = 100

        # Snapshot queue before removal.
        queue_before = len(check_ep_slot.entrypoint_queue)

        # Remove — not READY, so the entrypoint-fetching branch is skipped entirely.
        check_ep_slot.remove_connection(proto_C)

        assert check_ep_slot.rebound_slot is None
        assert len(check_ep_slot.entrypoint_queue) == queue_before

        # --- Phase 6: peer_A unblacklisted after TIME_PENALTY, reconnects, reaches READY ---
        # Advance clock past TIME_PENALTY (600s).
        self.simulator._clock.advance(601)

        # Reconnect peer_A — same FakeConnection, same entrypoint.
        conn_A.reconnect()
        self.simulator.add_connection(conn_A)
        self.simulator.run(1)

        # Blacklist expired — connection accepted into check_ep_slot.
        assert len(check_ep_slot) == 1
        assert addr_A not in blacklisted_set.entrypoint_set
        assert addr_A not in blacklisted_set.time_map

        # peer_A's entrypoint was never queued, so it is NOT in seen_entrypoints.
        # When removed as READY, the unseen path will try to fetch peer_A's advertised
        # entrypoints — but peer_A has no extra entrypoints, so nothing gets queued.
        assert addr_A not in check_ep_slot.seen_entrypoints

        # Force READY and safe timeout.
        conn_A.proto2.connection_state = ConnectionState.READY
        conn_A.proto2.diff_timestamp = 10
        conn_A.proto2.idle_timeout = 100

        # Disconnect — removed as READY + unseen, but peer has no extra entrypoints to queue.
        conn_A.disconnect(Failure(Exception('peer_A finally checked')))
        self.simulator.remove_connection(conn_A)
        self.simulator.run(1)

        # --- Final assertions: everything drained ---
        assert len(check_ep_slot.connection_slot) == 0
        assert check_ep_slot.rebound_slot is None
        assert len(check_ep_slot.entrypoint_queue) == 0
        assert len(blacklisted_set.entrypoint_set) == 0
        assert len(blacklisted_set.time_map) == 0

        # The extra entrypoints from peer_B were seen (via put_on_queue).
        assert extra_ep_1.addr in check_ep_slot.seen_entrypoints
        assert extra_ep_2.addr in check_ep_slot.seen_entrypoints
