import asyncio
import logging
import sys
import struct


logging.basicConfig(
    level=logging.DEBUG,
    format='[%(levelname)s][%(name)s %(asctime)s]:%(message)s',
    # filename='gms_multicaster.log',
    filemode='a',
    stream=sys.stderr
    )

log = logging.getLogger('asyncio_sock')
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
    def __init__(self, reader, writer):
        self.peername = writer.get_extra_info('peername')
        self.reader = reader
        self.writer = writer
        self.dst_reader = None
        self.dst_writer = None
        self.dst = None
        self.controller = FSM(self.negotiate)

    def shutdown(self):
        if self.writer.can_write_eof():
            self.writer.write_eof()
        if self.dst_writer:
            if self.dst_writer.can_write_eof():
                self.dst_writer.write_eof()
            self.dst_writer.close()

    async def negotiate(self, data):
        logging.info("Negotiation, from: {}, data: {}".
                     format(self.peername, data))
        if data[0] != 5:
            self.shutdown()
        else:
            self.writer.write(b'\x05\x00')
            self.controller.set_state(self.request)

    async def request(self, data):
        logging.info("Request, from: {}, data: {}".format(self.peername, data))
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
            self.dst_reader, self.dst_writer = \
                await asyncio.open_connection(*self.dst)
        except Exception as e:
            logging.error(str(e))
            self.shutdown()
            return

        self.writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        self.controller.set_state(self.trans)

    async def trans(self, data):
        logging.info("Transmitting, peer1: {}, peer2: {}".
                     format(
                         self.peername,
                         self.dst_writer.get_extra_info('peername')
                     ))

        self.dst_writer.write(data)
        await asyncio.wait([
            self.midman(self.dst_reader, self.writer),
            self.midman(self.reader, self.dst_writer)
        ])
        self.shutdown()

    @classmethod
    async def midman(cls, reader, writer):
        while True:
            data = await reader.read(4096)
            if not data:
                if writer.can_write_eof():
                    writer.write_eof()
                return
            writer.write(data)
            await writer.drain()


async def ConnectionFactory(reader, writer):
    peer = Client(reader, writer)
    log.info("New Connection From: {}".format(
        peer.peername
    ))

    while True:
        data = await reader.read(4096)
        if not data:
            if writer.can_write_eof():
                writer.write_eof()
            writer.close()
            log.info("Disconnect: {}".format(
                peer.peername
            ))
            return
        await peer.controller.update(data)


if __name__ == '__main__':
    if len(sys.argv) == 3:
        server_address = (sys.argv[1], sys.argv[2])
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
