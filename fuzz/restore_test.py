import sys, threading, time, os
import pickle
import ctypes

sys.path.append("../..")
from qiling import *
from qiling.os.posix.syscall.unistd import ql_syscall_vfork

class save_status:
    def __init__(self):
        self.all_mem = None
        self.all_context = None

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
    b"friendly_name=WNDR4000",
]))


def my_recvfrom(ql, *argu, **kw):
    regreturn = 3274
    ql.os.definesyscall_return(regreturn)


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
    ql.mem.write(0x7ff4ad8c, b"\x41"*3724)


def bug_show(ql, *argu, **kw):
    print('+++++++++++++++', ql.reg.read("R0"))
    print('+++++++++++++++', ql.mem.read(ql.reg.read("R0"), 0x100))
    print('\n\n+++Bug Here! R4==' + hex(ql.reg.read("R4")) + '!!!!!!!!!!\n\n')
    # exit(0)


def save_init(ql, *argu, **kw):
    ql.save(snapshot='snap')
    print('//////////save success//////////////')


def init():
    ql = Qiling(["./rootfs/usr/sbin/upnpd"], 
        "./rootfs", 
        output="off", console=True, profile="r6400.ql")
    ql.add_fs_mapper("/dev/nvram", fake_nvram)
    ql.add_fs_mapper("/dev/urandom", "/dev/urandom")
    ql.set_syscall(0x2, ql_syscall_vfork)
    ql.set_syscall(292, my_recvfrom)

    ql.hook_address(wr_flag, 0x1A420)
    ql.hook_address(wr_flag, 0x1A45C)
    ql.hook_address(save_init, 0x222C0)  # 0x1A41C)

    endpoint = 0x222C0+4  # 0x1A420
    ql.run(end=endpoint)


class send_pkt(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        import socket
        ip = '127.0.0.1'
        port = 1900
        time.sleep(3)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((ip, port))
        sock.send(b"\x41")
        print('****Send Success*****')


class fuzz_init(threading.Thread):
    def __init__(self, mutex):
        threading.Thread.__init__(self)
        self.mutex = mutex

    def run(self):
        self.mutex.acquire()
        init()
        self.mutex.release()


def main():
    ql = Qiling(["./rootfs/usr/sbin/upnpd"], 
    "./rootfs", 
    output="debug", verbose=4,console=True, profile="r6400.ql")

    ql.restore(snapshot='snap')

    ql.add_fs_mapper("/dev/nvram", fake_nvram)
    ql.add_fs_mapper("/dev/urandom", "/dev/urandom")
    ql.set_syscall(0x2, ql_syscall_vfork)
    ql.set_syscall(292, my_recvfrom)

    # ql.hook_address(wr_flag, 0x1A420)
    # ql.hook_address(wr_flag, 0x1A45C)

    ql.hook_address(wr_data, 0x222C4)

    ql.hook_address(mem_watch, 0x222CC)
    ql.hook_address(bug_show, 0xb80c)

    # --- Bug trigger at 0xB80C, R0=R4=can not access ---

    beginpoint = 0x222C0
    endpoint = 0x222D8
    ql.run(begin=beginpoint, end=endpoint)



if __name__ == "__main__":
    mutex1 = threading.Lock()
    thread_send = send_pkt()
    thread_fuzz = fuzz_init(mutex1)

    thread_send.start()
    thread_fuzz.start()
    thread_fuzz.join()
    thread_send.join()

    print('exittttttt')
    main()