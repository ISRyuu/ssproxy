import asyncio
import sys
import logging
from transporter import Transporter, GCMTransporter


logging.basicConfig(
    level=logging.DEBUG,
    format='[%(levelname)s][%(name)s %(asctime)s]:%(message)s',
    # filename='ss_client.log',
    filemode='a',
    stream=sys.stderr
)

log = logging.getLogger('ss_client')


async def ConnectionFactory(server, reader, writer):
    log.info("new connection from {}".format(
        writer.get_extra_info("peername"))
    )
    trans = Transporter(reader, writer)
    try:
        proxy_reader, proxy_writer = await asyncio.open_connection(*server)
        log.info("connected to proxy: {}".format(
            proxy_writer.get_extra_info("peername")
        ))
    except Exception as e:
        log.warn("cannot connect to proxy server, {}".format(e))
        return
    dst_trans = GCMTransporter(
        proxy_reader,
        proxy_writer,
        b"helloworld",
        writer.get_extra_info("peername")[0].encode('utf8')
    )

    await asyncio.wait([
        Transporter.midman(trans, dst_trans),
        Transporter.midman(dst_trans, trans),
    ])

    dst_trans.close()
    trans.close()
    log.info("finished")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("usage: ss_client [addr:port] [server_addr:server_port]")
        exit(1)
    local_address = sys.argv[1].split(':')
    server_address = sys.argv[2].split(':')
    event_loop = asyncio.get_event_loop()

    factory = asyncio.start_server(
        lambda x, y: ConnectionFactory(server_address, x, y),
        *local_address
    )
    server = event_loop.run_until_complete(factory)

    try:
        event_loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        event_loop.run_until_complete(server.wait_closed())
        event_loop.close()
        log.info("event loop closed")
