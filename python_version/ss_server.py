import asyncio
import logging
import sys
import struct
from transporter import Transporter, GCMTransporter


logging.basicConfig(
    level=logging.DEBUG,
    format='[%(levelname)s][%(name)s %(asctime)s]:%(message)s',
    # filename='gms_multicaster.log',
    filemode='a',
    stream=sys.stderr
    )

log = logging.getLogger('ss_server')
server_address = ('0.0.0.0', 9999)


class FSM(object):
    def __init__(self, state=None):
        self.state = state

    async def update(self, *args, **kargs):
        if self.state:
            await self.state(*args, **kargs)

    def set_state(self, state):
        self.state = state


class Client(object):
    def __init__(self, transporter):
        self.peername = transporter.writer.get_extra_info('peername')
        self.transporter = transporter
        self.dst_transporter = None
        self.dst = None
        self.controller = FSM(self.negotiate)

    def shutdown(self):
        if self.transporter.can_write_eof():
            self.transporter.write_eof()
        if self.dst_transporter:
            self.dst_transporter.close()

    async def negotiate(self, data):
        log.info("Negotiation, from: {}, data: {}".
                 format(self.peername, data))
        if data[0] != 5:
            self.shutdown()
        else:
            await self.transporter.send(b'\x05\x00')
            self.controller.set_state(self.request)

    async def request(self, data):
        log.info("Request, from: {}, data: {}".format(self.peername, data))
        if len(data) <= 6:
            self.shutdown()
            return
        if data[0] != 5 or data[1] != 1 or data[2] != 0:
            self.shutdown()
            return
        atype = data[3]
        addr = data[4:-2]
        port, = struct.unpack("!H", data[-2:])
        if atype == 1:
            # ipv4
            addr = '.'.join(str(x) for x in addr)
        elif atype == 3:
            # domain
            length = addr[0]
            addr = addr[1:].decode('utf8')  # trim length
            if len(addr) != length:
                self.shutdown()
                return
        elif atype == 4:
            # ipv6
            # no much difference between ipv4 and ipv6
            self.shutdown()
            return
        else:
            self.shutdown()
            return
        self.dst = (addr, port)
        self.controller.set_state(self.connect_dst)
        await self.controller.update()

    async def connect_dst(self):
        try:
            dst_reader, dst_writer = \
                await asyncio.open_connection(*self.dst)
            log.info("connected to server: {}".format(self.dst))
        except Exception as e:
            log.error(str(e))
            self.shutdown()
            return

        self.dst_transporter = Transporter(dst_reader, dst_writer)
        await self.transporter.send(
            b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        )
        self.controller.set_state(self.trans)

    async def trans(self, data):
        log.info("Transmitting, peer1: {}, peer2: {}".
                     format(
                         self.peername,
                         self.dst_transporter.writer.get_extra_info('peername')
                     ))

        await self.dst_transporter.send(data)
        await asyncio.wait([
            Transporter.midman(self.transporter, self.dst_transporter),
            Transporter.midman(self.dst_transporter, self.transporter)
        ])
        self.shutdown()


async def ConnectionFactory(reader, writer):
    # For socks5 server, use non-encrypted Transporter.
    # t = Transporter(reader, writer)
    t = GCMTransporter(
        reader, writer, b"helloworld",
        writer.get_extra_info("sockname")[0].encode('utf8')
    )

    peer = Client(t)
    log.info("New Connection From: {}".format(
        peer.peername
    ))

    while True:
        data = await t.recv()
        if not data:
            if t.can_write_eof():
                t.write_eof()
            t.close()
            log.info("Disconnect: {}".format(
                peer.peername
            ))
            return
        await peer.controller.update(data)


if __name__ == '__main__':
    if len(sys.argv) == 2:
        server_address = sys.argv[1].split(':')
    event_loop = asyncio.get_event_loop()
    factory = asyncio.start_server(
        ConnectionFactory,
        *server_address
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
