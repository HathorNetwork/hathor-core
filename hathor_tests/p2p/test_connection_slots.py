from hathor.p2p.connection_slot import SlotsManager, SlotsManagerSettings
from hathor.simulator import FakeConnection
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
        max_connections = max_bootstrap + max_incoming + max_outgoing

        # Set SlotsManager Settings:
        slots_manager_settings = SlotsManagerSettings(max_outgoing, max_incoming, max_bootstrap)

        # Set SlotsManager:
        slots_manager = SlotsManager(slots_manager_settings)

        # Attribute it to the peer
        full_node.connections.slots_manager = slots_manager

        # For each connection type we add more peers than necessary to see if the slot limits it.
        # Create peer list for incoming connections
        in_peerList = []
        for _ in range(max_incoming + 1):
            in_peerList.append(self.create_peer())

        # Generate incoming connections - full_node is the target.
        in_connList = []
        for i in range(0, max_incoming + 1):
            in_connList.append(FakeConnection(full_node, in_peerList[i]))

        # Add connections to simulator.
        for i in range(len(in_connList)):
            self.simulator.add_connection(in_connList[i])

        self.simulator.run(10)

        incoming_slot = full_node.connections.slots_manager.incoming_slot
        number_incoming_slot = len(incoming_slot.connection_slot)
        # Checks whether the connection has capped on its limit size.
        self.assertTrue(number_incoming_slot == max_incoming)

        # We repeat the analysis for all other slots.

        # --- outgoing slot ---

        out_peerList = []
        for _ in range(max_outgoing + 1):
            out_peerList.append(self.create_peer())

        out_connList = []
        for i in range(0, max_outgoing + 1):
            out_connList.append(FakeConnection(out_peerList[i], full_node))

        for i in range(len(out_connList)):
            self.simulator.add_connection(out_connList[i])

        self.simulator.run(10)
        outgoing_slot = full_node.connections.slots_manager.outgoing_slot
        number_outgoing_slot = len(outgoing_slot.connection_slot)
        self.assertTrue(number_outgoing_slot == max_outgoing)

        # --- bootstrap slot ---
        bootstrap_peerList = []
        for _ in range(max_bootstrap + 1):
            bootstrap_peerList.append(self.create_peer())

        bootstrap_connList = []
        for i in range(0, max_bootstrap + 1):
            bootstrap_connList.append(FakeConnection(bootstrap_peerList[i], full_node, fake_bootstrap_id=None))

        for i in range(len(bootstrap_connList)):
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

        # Outgoing slot must not update
        outgoing_slot = full_node.connections.slots_manager.outgoing_slot
        self.assertTrue(len(outgoing_slot.connection_slot) == 0)

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

        incoming_slot = full_node.connections.slots_manager.incoming_slot
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

        bootstrap_slot = full_node.connections.slots_manager.bootstrap_slot
        self.assertTrue(len(bootstrap_slot.connection_slot) == 0)

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
        pass


class CheckEntrypointsTestCase(SimulatorTestCase):
    def test_add_connection(self) -> None:
        pass

    def test_remove_connection(self) -> None:
        pass

    def test_add_one_when_full(self) -> None:
        pass

    def test_remove_when_queue_full(self) -> None:
        pass