"""Boyutu ve omru sinirli, is parcacigi guvenli bellek ici onbellek.

Moduller degerleri (zaman_damgasi, deger) cifti olarak saklar ve sureyi okurken kendileri
denetler. Bu sinif buna ek olarak toplam kayit sayisini sinirlar (en eski kayit atilir) ve
`max_age` saniyeden eski kayitlari temizler; boylece benzersiz girdilerle bellek doldurulamaz.
"""

import threading
import time
from collections import OrderedDict


class BoundedCache:
    def __init__(self, maxsize: int = 2048, max_age: float = 6 * 60 * 60):
        self.maxsize = maxsize
        self.max_age = max_age
        self._data: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key, default=None):
        with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return default
            if time.time() - entry[0] > self.max_age:
                del self._data[key]
                return default
            self._data.move_to_end(key)
            return entry

    def __setitem__(self, key, entry):
        with self._lock:
            self._data[key] = entry
            self._data.move_to_end(key)
            while len(self._data) > self.maxsize:
                self._data.popitem(last=False)

    def __len__(self):
        with self._lock:
            return len(self._data)

    def clear(self):
        with self._lock:
            self._data.clear()
