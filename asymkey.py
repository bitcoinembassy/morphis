# Copyright (c) 2014-2015  Sam Maloney.
# License: LGPL.

class AsymKey():
    def _write_private_key_file(self, tag, filename, data, password):
        with open(filename, 'wb') as f:
            return self._write_private_key(tag, f, data, password)

    def _write_private_key(self, tag, fileobj, data, password):
        fileobj.write(data)

    def _read_private_key_file(self, tag, filename, password):
        with open(filename, 'rb') as f:
            return self._read_private_key(tag, f, password)

    def _read_private_key(self, tag, fileobj, password):
        return fileobj.read()
