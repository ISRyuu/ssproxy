import struct
import asyncio
import os
from gcm_encrypt import decrypt, encrypt


def create_receiver(reader, meta_size, trunk=4096):
    buff = b''
    clen = 0
    ClenSize = 2
    recv = True

    async def _recv():

        nonlocal buff
        nonlocal clen
        nonlocal recv

        while True:
            if recv:
                data = await reader.read(trunk)
                if not data:
                    return data
                buff += data
                recv = False

            msg_len = len(buff)

            if clen == 0:
                if msg_len < meta_size + ClenSize:
                    recv = True
                    continue

                clen, = struct.unpack_from('!H', buff, meta_size)

            if msg_len >= clen:
                ret = buff[:clen]
                buff = buff[clen:]
                clen = 0
                return ret

            recv = True

    return _recv


def pack_data(data, meta_data):
    ClenSize = 2
    length = len(data) + len(meta_data) + ClenSize
    # |--IV(12 bytes)--|--tag(16 bytes)--|--len(2 bytes)--|--payload(len-12-16-2 bytes)--|
    # len is in network-byte-order (big-endian)
    data = meta_data + struct.pack('!H', length) + data
    return data


class Transporter(object):
    def __init__(self, reader, writer, trunk=4096):
        self.reader = reader
        self.writer = writer
        self.trunk = trunk

    async def send(self, data):
        self.writer.write(data)
        await self.writer.drain()

    async def recv(self):
        return await self.reader.read(self.trunk)

    def close(self):
        self.writer.close()

    def write_eof(self):
        self.writer.write_eof()

    def can_write_eof(self):
        return self.writer.can_write_eof()

    @classmethod
    async def midman(cls, reader, writer):
        while True:
            data = await reader.recv()
            if not data:
                if writer.can_write_eof():
                    writer.write_eof()
                return
            await writer.send(data)


class GCMTransporter(Transporter):
    def __init__(self, reader, writer, secret, associated_data, trunk=4096):
        super().__init__(reader, writer, trunk)
        self._secret = secret
        self._associated_data = associated_data
        # 12: IV length, 16: calculated tag length
        self.receiver = create_receiver(reader, 12 + 16)

    async def send(self, data):
        iv, cipher, tag = encrypt(self._secret, data, self._associated_data)
        await super().send(pack_data(cipher, iv + tag))

    async def recv(self):
        data = await self.receiver()
        if not data:
            return data
        iv = data[:12]
        tag = data[12:12+16]
        # 2: ClenSize
        payload = data[12+16+2:]
        return decrypt(self._secret, self._associated_data, iv, payload, tag)


# Testing Code
async def reader_with_fo(loop, fo):
    reader = asyncio.StreamReader(loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, fo)
    return reader


async def writer_with_fo(loop, fo):
    writer_transport, writer_protocol = \
        await loop.connect_write_pipe(asyncio.streams.FlowControlMixin, fo)
    writer = asyncio.StreamWriter(
        writer_transport, writer_protocol, None, loop
    )
    return writer


async def Rf(loop, r):
    r = os.fdopen(r, 'rb')
    reader = await reader_with_fo(loop, r)
    Recv = create_receiver(reader, 16, 2)
    while True:
        data = await Recv()
        if not data:
            r.close()
            return
        print(data)


async def Wf(loop, w):
    w = os.fdopen(w, 'wb')
    writer = await writer_with_fo(loop, w)
    writer.write(pack_data(b'hello world', b'0'*16))
    writer.write(pack_data(b'1', b'0'*16))
    writer.write(
        pack_data(b'manymanymanymanymanymanymanymanymanymanymanymany'
                  b'manymanymanymanymanymanymanymanymanymanymanymanymanymany'
                  b'manymanymanymanymanymanymanymanymanymany bytes', b'0'*16)
    )
    writer.write_eof()
    writer.close()


def test():
    loop = asyncio.get_event_loop()
    r, w = os.pipe()

    try:
        loop.run_until_complete(asyncio.wait([Rf(loop, r), Wf(loop, w)]))
    except Exception:
        pass
    finally:
        loop.close()


if __name__ == '__main__':
    test()
