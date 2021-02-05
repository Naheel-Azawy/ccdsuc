import logging
import os
import math
import hashlib

from errno     import EACCES
from os.path   import realpath
from threading import Lock

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn

from Crypto.Cipher import AES
from Crypto.Util   import Counter
from Crypto.Random import get_random_bytes

LOG = True

def log(msg):
    if LOG:
        print(msg)

class CryptoFS(LoggingMixIn, Operations):
    """Files are stored as follows:
    +----+--------------+--------+---------+
    | iv | padding size |  data  | padding |
    +----+--------------+--------+---------+
      16        1           ...     0..15    <- sizes in bytes
    """

    def __init__(self, root, mount):
        self.root = realpath(root)
        self.mount = realpath(mount)
        self.block_size = AES.block_size
        self.rwlock = Lock()

    def __call__(self, op, path, *args):
        log(f">>> __call__({op}, {path})")
        return super(CryptoFS, self).__call__(op, path, *args)

    def access(self, path, mode):
        path = self.translate_path(path)
        if not os.access(path, mode):
            raise FuseOSError(EACCES)

    def chmod(self, path, mode):
        path = self.translate_path(path)
        return os.chmod(path, mode)

    def chown(self, path, uid, gid):
        path = self.translate_path(path)
        return os.chown(path, uid, gid)

    def create(self, path, mode):
        path = self.translate_path(path)
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)

    def flush(self, path, fh):
        return os.fsync(fh)

    def fsync(self, path, datasync, fh):
        if datasync != 0:
            return os.fdatasync(fh)
        else:
            return os.fsync(fh)

    def getattr(self, path, fh=None):
        path = self.translate_path(path)
        st = os.lstat(path)
        attr = dict((key, getattr(st, key)) for key in (
            'st_atime', 'st_ctime', 'st_gid', 'st_mode', 'st_mtime',
            'st_nlink', 'st_size', 'st_uid'))
        # hide the IV size and the padding_size size
        attr['st_size'] -= (self.block_size + 1)
        # hide the padding itself
        try:
            with self.rwlock:
                if fh is None:
                    tmpf = os.open(path, os.O_RDONLY)
                else:
                    tmpf = fh
                os.lseek(tmpf, self.block_size, os.SEEK_SET)
                padding_size = os.read(tmpf, 1)
                padding_size = int.from_bytes(padding_size, "big")
                if fh is None:
                    os.close(tmpf)
                attr['st_size'] -= padding_size
        except:
            # probably it will fail reading a directory
            # I guess this should be handled in a nicer way
            pass
        if attr['st_size'] < 0:
            attr['st_size'] = 0
        print(attr)
        return attr

    getxattr = None
    listxattr = None

    def link(self, target, source):
        target = self.translate_path(target)
        source = self.translate_path(source)
        return os.link(source, target)

    def mkdir(self, path, mode):
        path = self.translate_path(path)
        return os.mkdir(path, mode)

    def mknod(self, path, mode, dev):
        path = self.translate_path(path)
        return os.mknod(path, mode, dev)

    def open(self, path, flags):
        log(f">>> open({path}, {flags})")
        path = self.translate_path(path)
        # if the file is open in read only mode,
        # we open in read/write instead.
        # this is important to read the IV and unaligned blocks
        if flags & os.O_WRONLY != 0:
            flags &= ~os.O_WRONLY # remove the read only flag
            flags |= os.O_RDWR    # add the read/write flag
        # O_APPEND prevents seeking to any offset
        if flags & os.O_APPEND != 0:
            flags &= ~os.O_APPEND # remove the append flag
            flags |= os.O_RDWR    # add the read/write flag, just in case
        log(f">>> new flags = {flags}")
        return os.open(path, flags)

    def readdir(self, path, fh):
        return ['.', '..'] + self.lsdir(path)

    def readlink(self, path):
        path = self.translate_path(path)
        return os.readlink(path)

    def release(self, path, fh):
        return os.close(fh)

    def rename(self, old, new):
        old = self.translate_path(old)
        new = self.translate_path(new)
        return os.rename(old, new)

    def rmdir(self, path):
        path = self.translate_path(path)
        return os.rmdir(path)

    def statfs(self, path):
        path = self.translate_path(path)
        stv = os.statvfs(path)
        return dict((key, getattr(stv, key)) for key in (
            'f_bavail', 'f_bfree', 'f_blocks', 'f_bsize', 'f_favail',
            'f_ffree', 'f_files', 'f_flag', 'f_frsize', 'f_namemax'))

    def symlink(self, target, source):
        target = self.translate_path(target)
        source = self.translate_path(source)
        return os.symlink(source, target)

    def truncate(self, path, length, fh=None):
        path = self.translate_path(path)
        # add the length of the file size and the IV
        length += self.block_size
        with open(path, 'rb+') as f:
            f.truncate(length)

    def unlink(self, path):
        path = self.translate_path(path)
        return os.unlink(path)

    def utimens(self, path, times=None):
        path = self.translate_path(path)
        return os.utime(path, times)

    def read(self, path, size, offset, fh):
        log(f">>> read({path}, {size}, {offset}, {fh})")
        virt_path = path
        path = self.translate_path(path)
        with self.rwlock:
            plaintext, first_block_num, seq_size, file_size, iv = \
                self.read_blocks(path, virt_path, size, offset, fh)

            # return only the needed parts
            offset_rem = offset % self.block_size
            return plaintext[offset_rem:(offset_rem + size)]

    def write(self, path, data, offset, fh):
        log(f">>> write({path}, len:{len(data)}, {offset}, {fh})")
        virt_path = path
        path = self.translate_path(path)
        size = len(data)
        with self.rwlock:
            # this is needed to ensure that the file is written to the disk.
            # otherwise, large files will cause "bad file descriptor"
            fh = os.open(path, os.O_RDWR)
            
            plaintext, first_block_num, seq_size, file_size, iv = \
                self.read_blocks(path, virt_path, size, offset, fh)
            is_new = not bool(iv)

            log(f">>>> {plaintext}, {first_block_num}, {seq_size}, {file_size}, {iv}\n")

            if is_new:
                log(">>>> new file")
                if offset != 0:
                    # writing with an offset to a new file
                    return -1
                # create a new IV
                iv = get_random_bytes(self.block_size)
                new_data = data
            else:
                log(">>>> modifying existing file")
                # concat the changed parts with the old parts
                offset_rem = offset % self.block_size
                new_data = plaintext[0:offset_rem] + data + plaintext[offset_rem + size:]

            # if at the end of the file, pad
            if offset + size >= file_size:
                log(">>>> padding")
                #log(new_data)
                padding_size = math.ceil(len(new_data) / self.block_size) * self.block_size - len(new_data)
                log(f">>>> len(new_data)={len(new_data)}, padding_size={padding_size}")
                new_data = new_data + bytes([padding_size] * padding_size)

            # create the cipher and encrypt
            cipher = self.mkcipher(virt_path, iv, first_block_num)
            ciphertext = cipher.encrypt(new_data)
            #log(">>>> plaintext:")
            #log(new_data)
            #log(">>>> ciphertext:")
            #log(ciphertext)
            #log(ciphertext.hex())
            #log(">>>> iv:")
            #log(iv.hex())

            if is_new:
                # write the new data with the iv and padding_size
                os.lseek(fh, 0, os.SEEK_SET)
                ret = os.write(fh, iv)
                if ret != len(iv):
                    ret = -1
                else:
                    ret = os.write(fh, bytes([padding_size]))
                    if ret != 1:
                        ret = -1
                    else:
                        ret = os.write(fh, ciphertext)
            else:
                # write the new padding_size
                log(f">>>> os.lseek({fh}, {self.block_size}, os.SEEK_SET)")
                os.lseek(fh, self.block_size, os.SEEK_SET)
                log(f">>>> ret = os.write({fh}, {bytes([padding_size])})")
                ret = os.write(fh, bytes([padding_size]))
                log(f"<<<< {ret}")
                if ret != 1:
                    ret = -1
                else:
                    # write back the new data
                    log(f">>>> os.lseek({fh}, {self.block_size} + 1 + {first_block_num} * {self.block_size}, os.SEEK_SET)")
                    os.lseek(fh, self.block_size + 1 + first_block_num * self.block_size, os.SEEK_SET)
                    log(f">>>> ret = os.write({fh}, {ciphertext})")
                    ret = os.write(fh, ciphertext)
                    log(f"<<<< {ret}")

            if ret != len(ciphertext):
                ret = -1
            else:
                ret = size

            os.close(fh)
            return ret

    # below are extra functions unrelated to fuse

    def mkcipher(self, path, iv, first_block_num=0):
        """Creates a counter and an AES cipher with CTR mode.
        Args:
          path (str):
            the virtual path of the file from the mount point
          iv (bytes):
            16 bytes initialization vector
          first_block_num (int):
            number of the first block to be used as the counter
        """

        key = self.key_gen(path, iv)
        # the counter starts with the value of iv and adds
        # the offset if any.
        ctr = Counter.new(8 * self.block_size,
                          initial_value=(int.from_bytes(iv, "big") + first_block_num))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        return cipher

    def read_blocks(self, path, virt_path, size, offset, fh):
        log(f">>>> read_blocks({path}, {virt_path}, {size}, {offset}, {fh})")

        if not os.path.exists(path):
            log("does not exist")
            return b'', 0, 0, 0, b''

        os.lseek(fh, 0, os.SEEK_SET)

        try:
            iv = os.read(fh, self.block_size)
        except Exception as e:
            log(">>>> err: couldn't get the iv")
            log(e)
            return b'', 0, 0, 0, b''

        if len(iv) != self.block_size:
            # empty or tiny corrupted file
            log(f">>>> err: empty or tiny corrupted file (len(iv) = {len(iv)})")
            return b'', 0, 0, 0, iv

        try:
            padding_size = os.read(fh, 1)
        except:
            log(">>>> err: couldn't get padding size")
            return b'', 0, 0, 0, iv

        if len(padding_size) != 1:
            # empty or tiny corrupted file
            log(">>>> err: empty or tiny corrupted file (padding size too small)")
            return b'', 0, 0, 0, iv
        else:
            padding_size = int.from_bytes(padding_size, "big")

        # real file size = size of the encrypted file - size of the IV
        #                  - size of the padding_size - padding_size itself
        file_size = os.path.getsize(path) - self.block_size - 1 - padding_size
        log(path)
        log(os.path.getsize(path))
        log(file_size)

        if offset > file_size:
            log(">>>> err: offset > file_size")
            return b'', 0, 0, file_size, iv

        old_size = 0
        if offset + size > file_size:
            old_size = size
            size = file_size - offset

        first_block_num = offset // self.block_size
        seq_size = size + (offset % self.block_size)

        # fill extra bytes to obtain a sequence length which is a multiple of the block size
        if (offset + size) % self.block_size != 0:
            seq_size += self.block_size - ((offset + size) % self.block_size)

        # read block sequence, skip the iv and padding_size
        os.lseek(fh, self.block_size + 1 + first_block_num * self.block_size, os.SEEK_SET)
        blocks = os.read(fh, seq_size)

        if len(blocks) != seq_size:
            log(">>>> err: couldn't read the whole seq_size")
            log(f">>>> len(blocks)={len(blocks)}, seq_size={seq_size}")
            return b'', first_block_num, seq_size, file_size, iv

        # create the cipher and decrypt
        cipher = self.mkcipher(virt_path, iv, first_block_num)
        plaintext = cipher.decrypt(blocks)

        # if at the end of the file, pad
        if padding_size > 0 and offset + size >= file_size:
            log(f">>>> unpadding {padding_size} bytes")
            #log(plaintext)
            plaintext = plaintext[0:-padding_size]
            #log(plaintext)

        log(f">>>> size = {size}, offset = {offset}, first_block_num = {first_block_num}, seq_size = {seq_size}, file_size = {file_size}, iv = {iv}")

        return plaintext, first_block_num, seq_size, file_size, iv

    def key_gen(self, path, iv):
        """To be overridden in a child class"""
        # needs to be 32 bytes long
        return b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'

    def translate_path(self, path):
        """To be overridden in a child class"""
        return self.root + path

    def lsdir(self, path):
        """To be overridden in a child class"""
        path = self.translate_path(path)
        return os.listdir(path)

    def fsname(self):
        """Label of the filesystem"""
        return self.__class__.__name__

    def start(self):
        """Mounts encrypted <root> to <mount> using <fs> (e.g. CryptoFS)"""
        if LOG:
            logging.basicConfig(level=logging.DEBUG)
        return FUSE(self, self.mount, foreground=True, allow_other=True,
                    fsname=self.fsname())

def main(args):
    CryptoFS(args[1], args[2]).start()
