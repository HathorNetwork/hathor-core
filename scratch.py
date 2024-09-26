from twisted.internet.defer import Deferred

from hathor.multiprocess.process_rpc import ProcessRPC
from hathor.p2p.sync_v2.sync_process_rpc import MyProcessRPCHandler, RequestB
from hathor.reactor import initialize_global_reactor, get_global_reactor


async def run_sub(subprocess_rpc: ProcessRPC) -> None:
    response = await subprocess_rpc.call(RequestB(b='sub1'))
    response = await subprocess_rpc.call(RequestB(b='sub2'))


async def run_main() -> None:
    main_reactor = get_global_reactor()
    main_rpc = ProcessRPC.fork(
        main_reactor=main_reactor,
        target=run_sub,
        subprocess_name='sub',
        main_handler=MyProcessRPCHandler(),
        subprocess_handler=MyProcessRPCHandler(),
    )
    response = await main_rpc.call(RequestB(b='main3'))
    response = await main_rpc.call(RequestB(b='main4'))


if __name__ == '__main__':
    reactor = initialize_global_reactor()
    reactor.callWhenRunning(lambda: Deferred.fromCoroutine(run_main()))
    reactor.run()
