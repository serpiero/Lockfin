GridBackground.qml copied unmodified from flipperdevices/qFlipper.
Commit: 1d26683ff5b751f219a4e40443b7c8355eb39469
Source: https://raw.githubusercontent.com/flipperdevices/qFlipper/1d26683ff5b751f219a4e40443b7c8355eb39469/application/components/GridBackground.qml
The QPainter port in desktop.GridPanel preserves the original geometry, gradient stops, opacity and 4-second linear scanline animation. Distributed under GPL-3.0; see LICENSE.

controls/{windows,mac} contains the unmodified minimize and close SVGs and their hover/pressed states from application/assets/gfx/controls at the same commit. TitleBar uses the platform layout from WindowControls.qml. ChromeFrame uses the border from MainWindow.qml.
