# PySide6, Shiboken6 and Qt notices

Lockfin Companion dynamically links PySide6-Essentials, Shiboken6 and Qt **6.12.0**, Copyright The Qt Company Ltd. and other contributors. These components are not authored by Lockfin. PySide6 and Shiboken6 are offered under LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only; the Qt modules used here are available under LGPLv3/GPLv3 and include separately licensed third-party components. Lockfin itself is GPL-3.0.

The full LGPLv3, GPLv3 and Qt GPL exception texts are in `licenses/`, copied without modification from the PySide 6.12.0 upstream release. Preserve these notices and upstream copyright/license files when redistributing. No commercial Qt license is claimed.

Matching source, component copyright notices, third-party attributions and build instructions:

- [PySide6/Shiboken6 6.12.0 source](https://code.qt.io/cgit/pyside/pyside-setup.git/tag/?h=v6.12.0)
- [Qt 6.12.0 source archives](https://download.qt.io/archive/qt/6.12/6.12.0/submodules/)
- [Qt licensing and third-party code](https://doc.qt.io/qt-6/licenses-used-in-qt.html)
- [Qt for Python licensing](https://doc.qt.io/qtforpython-6/licenses.html)

The native bundles contain the complete public Lockfin application source under `source/`, including its build scripts. The shared Qt libraries remain dynamically loaded; recipients may replace compatible libraries and rebuild from source. Reverse engineering for debugging modifications to LGPL-covered libraries is permitted under the applicable licenses. This application-source directory does not claim to contain the source of Qt, Python, OpenSSL or other upstream dependencies; the exact upstream sources above and their own licenses apply.
