from hathor.p2p.netfilter import get_table
from hathor.p2p.netfilter.chain import NetfilterChain
from hathor.p2p.netfilter.table import NetfilterTable
from hathor.p2p.netfilter.targets import NetfilterAccept
from hathor_tests import unittest


class NetfilterTableTest(unittest.TestCase):
    def test_default_table_filter(self) -> None:
        tb_filter = get_table('filter')
        tb_filter.get_chain('pre_conn')
        tb_filter.get_chain('post_hello')
        tb_filter.get_chain('post_peerid')

    def test_default_table_not_exists(self) -> None:
        with self.assertRaises(KeyError):
            get_table('do-not-exists')

    def test_add_get_chain(self) -> None:
        mytable = NetfilterTable('mytable')
        mychain = NetfilterChain('mychain', NetfilterAccept())
        mytable.add_chain(mychain)
        ret = mytable.get_chain('mychain')
        self.assertEqual(mychain, ret)

        with self.assertRaises(ValueError):
            mytable.add_chain(mychain)

        with self.assertRaises(KeyError):
            mytable.get_chain('do-not-exists')
