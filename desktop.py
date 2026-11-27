#!/usr/bin/env python3
"""Qt companion for local encrypted vaults."""
from pathlib import Path
from types import SimpleNamespace
from hashlib import md5
import argparse
import os
import sys
import tempfile
import math

from PySide6.QtCore import Qt, Signal, QThread, QEvent, QElapsedTimer, QTimer, QRectF, QUrl, QStandardPaths, QItemSelection, QItemSelectionModel
from PySide6.QtGui import QFont, QFontDatabase, QPainter, QPainterPath, QRegion, QColor, QPen, QLinearGradient, QIcon, QDesktopServices, QFontMetrics
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFrame, QLabel, QLayout, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QTableWidget, QTableWidgetItem, QHeaderView,
    QInputDialog, QFileDialog, QMessageBox, QDialog, QFormLayout, QDialogButtonBox, QStackedWidget, QToolButton, QSizeGrip, QSizePolicy, QStyledItemDelegate, QStyleOptionViewItem, QStyle,
)
from flipper_sync import DevicePull
import importers
import vault
import device_storage as device

VERSION = '0.6.9'
PROJECT = Path(__file__).resolve().parent
PRIVATE = PROJECT / 'private'


def load_fonts():
    for name in ('ShareTech-Regular.ttf', 'ShareTechMono-Regular.ttf', 'Born2bSportyV2.ttf', 'haxrcorp-4089.ttf', 'ProggySquare.ttf'):
        path = PROJECT / 'assets/fonts' / name
        if path.is_file():
            QFontDatabase.addApplicationFont(str(path))


def label(text, size=32, color='#ff9722', family='HaxrCorp 4089', *, crisp=False):
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    font = QFont(family)
    font.setPixelSize(size)
    if crisp:
        font.setStyleStrategy(QFont.StyleStrategy.NoAntialias)
        font.setHintingPreference(QFont.HintingPreference.PreferFullHinting)
    widget.setFont(font)
    widget.setStyleSheet(f'color:{color};background:transparent;')
    widget.setWordWrap(True)
    return widget


def pixel_font():
    font = QFont('HaxrCorp 4089')
    font.setPixelSize(32)
    font.setStyleStrategy(QFont.StyleStrategy.NoAntialias)
    font.setHintingPreference(QFont.HintingPreference.PreferFullHinting)
    return font


def action_button(text):
    button = QPushButton(text)
    button.setFont(pixel_font())
    return button


class GridPanel(QWidget):
    """GPL-3.0 port of qFlipper GridBackground.qml; upstream kept in third_party."""
    grid_columns = 30
    grid_step = 27  # qFlipper at its normal ~810 px width; fixed across resizes.
    accent = '#fe8a2c'
    scan_height = 320
    scan_duration = 4000

    def __init__(self, parent=None):
        super().__init__(parent)
        self.clock = QElapsedTimer()
        self.animation = QTimer(self)
        self.animation.setInterval(33)
        self.animation.timeout.connect(self.update)

    def showEvent(self, event):
        if not self.clock.isValid():
            self.clock.start()
        self.animation.start()
        super().showEvent(event)

    def hideEvent(self, event):
        self.animation.stop()
        super().hideEvent(event)

    def scan_y_at(self, milliseconds):
        phase = (milliseconds % self.scan_duration) / self.scan_duration
        return -self.scan_height + phase * (self.height() + self.scan_height)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        background = QLinearGradient(0, 0, 0, self.height())
        background.setColorAt(0, QColor('#090400'))
        background.setColorAt(1, QColor('#210F00'))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(background)
        painter.drawRoundedRect(QRectF(self.rect()), 9, 9)
        painter.save()
        painter.setClipRect(self.rect().adjusted(3, 3, -3, -3))
        elapsed = self.clock.elapsed() if self.clock.isValid() else 0
        y = 3 + self.scan_y_at(elapsed)
        scan = QLinearGradient(0, y, 0, y + self.scan_height)
        for position, alpha in ((0, 0), (0.6, 0.01), (0.99, 0.07), (1, 0)):
            color = QColor(self.accent); color.setAlphaF(alpha)
            scan.setColorAt(position, color)
        painter.fillRect(QRectF(3, y, self.width()-6, self.scan_height), scan)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        color = QColor('#aa5115'); color.setAlphaF(0.15)
        painter.setPen(QPen(color, 2))
        width, height = self.width()-6, self.height()-6
        cell = self.grid_step
        if cell > 0:
            pos = cell
            while pos < height:
                line = 3 + math.floor(pos)
                painter.drawLine(3, line, self.width()-3, line); pos += cell
            pos = cell
            while pos < width:
                line = 3 + math.floor(pos)
                painter.drawLine(line, 3, line, self.height()-3); pos += cell
        painter.restore()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(QColor(self.accent), 3))
        painter.drawRoundedRect(QRectF(self.rect()).adjusted(1.5, 1.5, -1.5, -1.5), 9, 9)


class AccountDelegate(QStyledItemDelegate):
    def editorEvent(self, event, model, option, index):
        return False if index.column() == 0 else super().editorEvent(event, model, option, index)

    def paint(self, painter, option, index):
        if index.column() != 0:
            return super().paint(painter, option, index)
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.features &= ~QStyleOptionViewItem.ViewItemFeature.HasCheckIndicator
        style = opt.widget.style() if opt.widget else QApplication.style()
        style.drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, opt.widget)
        painter.save()
        box = QRectF(option.rect.center().x()-5.5, option.rect.center().y()-5.5, 11, 11)
        painter.setPen(QPen(QColor('#ff9722'), 1))
        checked = index.data(Qt.ItemDataRole.CheckStateRole) == Qt.CheckState.Checked.value
        painter.setBrush(QColor('#ff9722' if checked else '#140900'))
        painter.drawRect(box)
        painter.restore()


class AccountTable(QTableWidget):
    row_toggled = Signal(int)

    def mousePressEvent(self, event):
        point = event.position().toPoint()
        index = self.indexAt(point)
        selected = self.selectionModel().selectedRows()
        self.toggle_point = point if (event.button() == Qt.MouseButton.LeftButton and
            not event.modifiers() and index.isValid() and len(selected) == 1 and
            selected[0].row() == index.row()) else None
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if getattr(self, 'toggle_point', None) is not None:
            if (event.position().toPoint()-self.toggle_point).manhattanLength() >= QApplication.startDragDistance():
                self.toggle_point = None
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        origin = getattr(self, 'toggle_point', None)
        super().mouseReleaseEvent(event)
        if origin is not None and self.indexAt(origin).row() == self.indexAt(event.position().toPoint()).row():
            self.clearSelection()
        self.toggle_point = None

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key.Key_Space, Qt.Key.Key_Return, Qt.Key.Key_Enter) and self.currentRow() >= 0:
            self.row_toggled.emit(self.currentRow())
            event.accept()
        else:
            super().keyPressEvent(event)


class ImportButton(QPushButton):
    file_dropped = Signal(str)

    def dragEnterEvent(self, event):
        if DropZone.dropped_path(event):
            event.acceptProposedAction()

    def dropEvent(self, event):
        path = DropZone.dropped_path(event)
        if path:
            event.acceptProposedAction()
            self.file_dropped.emit(str(path))


class ChromeFrame(QWidget):
    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setBrush(QColor('#000000'))
        painter.setPen(QPen(QColor('#662c00'), 2))
        painter.drawRoundedRect(QRectF(self.rect()).adjusted(1, 1, -1, -1), 9, 9)


class DropZone(QFrame):
    file_dropped = Signal(str)
    picker_requested = Signal()

    def __init__(self):
        super().__init__()
        self.setObjectName('dropZone')
        self.setAcceptDrops(True)
        self.setMinimumHeight(172)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 8, 18, 8)
        layout.setSpacing(4)
        layout.addStretch()
        for text, size, color, family in (
            ('+', 76, '#ff9722', 'Born2bSportyV2'),
            ('Drop your file here', 26, '#ff9722', 'Born2bSportyV2'),
            ('Or double-click the +', 16, '#fe8a2c', 'ProggySquareTT'),
            ('JSON · CSV · XML · TXT\nTSV · 1PUX · ZIP · LMV', 16, '#9e5823', 'ProggySquareTT'),
        ):
            widget = label(text, size, color, family, crisp=family == 'ProggySquareTT')
            widget.setAlignment(Qt.AlignmentFlag.AlignCenter)
            widget.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            layout.addWidget(widget)
        layout.addStretch()
        self.highlight(False)

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.picker_requested.emit()
            event.accept()
        else:
            super().mouseDoubleClickEvent(event)

    def highlight(self, active):
        self.setStyleSheet('QFrame#dropZone{background:rgba(0,0,0,100);border:2px dashed '+
                           ('#ff9722' if active else '#9e5823')+';border-radius:4px;}')

    @staticmethod
    def dropped_path(event):
        urls = event.mimeData().urls()
        if len(urls) != 1 or not urls[0].isLocalFile():
            return None
        path = Path(urls[0].toLocalFile())
        return path if path.is_file() and path.suffix.lower() in importers.EXTENSIONS else None

    def dragEnterEvent(self, event):
        if self.dropped_path(event):
            self.highlight(True)
            event.setDropAction(Qt.DropAction.CopyAction)
            event.accept()
        else:
            event.ignore()

    def dragMoveEvent(self, event):
        if self.dropped_path(event):
            event.setDropAction(Qt.DropAction.CopyAction)
            event.accept()

    def dragLeaveEvent(self, event):
        self.highlight(False)
        event.accept()

    def dropEvent(self, event):
        self.highlight(False)
        path = self.dropped_path(event)
        if path:
            event.setDropAction(Qt.DropAction.CopyAction)
            event.accept()
            self.file_dropped.emit(str(path))
        else:
            event.ignore()


class MasterDialog(QDialog):
    def __init__(self, parent, confirm=False):
        super().__init__(parent)
        self.setWindowTitle('Vault password')
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint |
                            Qt.WindowType.NoDropShadowWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setMinimumWidth(410)
        self.result_key = None
        shell = QVBoxLayout(self); shell.setContentsMargins(0, 0, 0, 0)
        frame = ChromeFrame(); shell.addWidget(frame)
        frame_layout = QVBoxLayout(frame); frame_layout.setContentsMargins(12, 8, 12, 12)
        frame_layout.addWidget(TitleBar(self, title='VAULT PASSWORD', minimize=False))
        panel = GridPanel(); frame_layout.addWidget(panel)
        layout = QVBoxLayout(panel); layout.setContentsMargins(16, 16, 16, 16)
        layout.addWidget(label('Password for PC and Flipper', 30, family='Born2bSportyV2'))
        form = QFormLayout()
        def entry():
            widget = QLineEdit()
            family = QApplication.font().family().replace('"', '')
            widget.setStyleSheet(f'QLineEdit{{font-family:"{family}";font-size:18px;padding:6px 8px;min-height:26px;}}')
            widget.setEchoMode(QLineEdit.EchoMode.Password)
            widget.setMaxLength(63)
            return widget
        self.first = entry()
        form.addRow(label('Password', 32), self.first)
        self.second = None
        if confirm:
            self.second = entry()
            form.addRow(label('Confirm', 32), self.second)
        layout.addLayout(form)
        layout.addWidget(label('Use 8–63 letters, numbers, spaces or symbols.\nNo accents, ñ or emoji (Flipper keyboard limit).', 16, '#fe8a2c', 'ProggySquareTT', crisp=True))
        self.validation_error = label('', 16, '#ff5b27', 'ProggySquareTT', crisp=True)
        self.validation_error.hide(); layout.addWidget(self.validation_error)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok |
                                   QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.validate)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def validate(self):
        try:
            vault.validate_master(self.first.text())
            if self.second and self.first.text() != self.second.text():
                raise vault.VaultError('Passwords do not match.')
        except vault.VaultError as exc:
            text = str(exc)
            if 'ASCII' in text:
                text = 'Use 8–63 letters, numbers, spaces or symbols; no accents or emoji.'
            self.validation_error.setText(text); self.validation_error.show()
            return
        self.result_key = self.first.text()
        self.accept()


class Window(QMainWindow):
    can_close = lambda self: True

    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint |
                            Qt.WindowType.NoDropShadowWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        QApplication.instance().installEventFilter(self)

    def eventFilter(self, watched, event):
        if (isinstance(watched, QWidget) and watched.window() is self and
                event.type() in (QEvent.Type.MouseMove, QEvent.Type.MouseButtonPress)):
            point = watched.mapTo(self, event.position().toPoint())
            edges = None
            for active, edge in ((point.x() < 6, Qt.Edge.LeftEdge),
                                 (point.x() >= self.width()-6, Qt.Edge.RightEdge),
                                 (point.y() < 6, Qt.Edge.TopEdge),
                                 (point.y() >= self.height()-6, Qt.Edge.BottomEdge)):
                if active:
                    edges = edge if edges is None else edges | edge
            if (edges is not None and event.type() == QEvent.Type.MouseButtonPress and
                    event.button() == Qt.MouseButton.LeftButton and self.windowHandle()):
                if self.windowHandle().startSystemResize(edges):
                    return True
        return super().eventFilter(watched, event)

    def closeEvent(self, event):
        pull = self.findChild(DevicePull)
        if pull and pull.isRunning():
            event.ignore()
            return
        event.accept() if self.can_close() else event.ignore()


class TitleBar(QWidget):
    def __init__(self, window, title=None, minimize=True):
        super().__init__()
        self.host_window = window
        self.drag_offset = None
        row = QHBoxLayout(self); row.setContentsMargins(0, 0, 0, 0)
        mac = sys.platform == 'darwin'
        row.setSpacing(8 if mac else 12)
        if mac:
            row.setDirection(QHBoxLayout.Direction.RightToLeft)
        if title:
            caption = label(title, 20, family='Born2bSportyV2')
            caption.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            row.addWidget(caption)
        row.addStretch()
        controls = PROJECT / 'third_party/qflipper/controls' / ('mac' if mac else 'windows')
        for tip, action in (('Minimize', window.showMinimized), ('Close', window.close)):
            if tip == 'Minimize' and not minimize:
                continue
            button = QToolButton()
            button.setFixedSize(20, 20)
            button.setToolTip(tip)
            button.setAccessibleName(tip)
            base = (controls / tip.lower()).as_posix()
            button.setStyleSheet(
                f'QToolButton {{border:0; padding:0; background:transparent; image:url("{base}.svg");}}'
                f'QToolButton:hover {{image:url("{base}_hover.svg");}}'
                f'QToolButton:pressed {{image:url("{base}_down.svg");}}')
            button.clicked.connect(action)
            row.addWidget(button)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            handle = self.host_window.windowHandle()
            if not handle or not handle.startSystemMove():
                self.drag_offset = event.globalPosition().toPoint() - self.host_window.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if self.drag_offset is not None and event.buttons() & Qt.MouseButton.LeftButton:
            self.host_window.move(event.globalPosition().toPoint() - self.drag_offset)

    def mouseReleaseEvent(self, event):
        self.drag_offset = None

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.host_window.showNormal() if self.host_window.isMaximized() else self.host_window.showMaximized()


def device_choice(parent, title, choices, *, detail=None):
    dialog = QDialog(parent, Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
    dialog.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
    dialog.setWindowTitle(title)
    shell = QVBoxLayout(dialog)
    shell.setContentsMargins(0, 0, 0, 0)
    frame = ChromeFrame()
    shell.addWidget(frame)
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(18, 16, 18, 16)
    layout.setSpacing(6)
    if detail is None:
        heading = label(title, 32, crisp=True)
        heading.setWordWrap(False)
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(heading)
    else:
        layout.addWidget(TitleBar(dialog, title=title, minimize=False))
        layout.addWidget(label(detail, 32, crisp=True))
    for index, text in enumerate(choices, 1):
        button = action_button(text)
        button.setFixedHeight(40)
        button.clicked.connect(lambda checked=False, result=index: dialog.done(result))
        layout.addWidget(button)
    frame.setMinimumWidth(340)
    shell.setSizeConstraint(QLayout.SizeConstraint.SetFixedSize)
    result = dialog.exec()
    dialog.deleteLater()
    return result


class TransferDialog(QDialog):
    def resizeEvent(self, event):
        super().resizeEvent(event)
        outline = QPainterPath()
        outline.addRoundedRect(QRectF(self.rect()), 10, 10)
        self.setMask(QRegion(outline.toFillPolygon().toPolygon()))


class TransferDots(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(28, 12)
        self.phase = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.advance)
        self.timer.start(300)

    def advance(self):
        self.phase = (self.phase + 1) % 3
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        for index in range(3):
            color = '#ff9722' if index == self.phase else '#985721'
            painter.fillRect(2 + index * 9, 3, 6, 6, QColor(color))


class DeviceOperation(QThread):
    def __init__(self, function, args, parent):
        super().__init__(parent)
        self.function, self.args = function, args
        self.error = None

    def run(self):
        try:
            self.function(*self.args)
        except (ValueError, OSError) as exc:
            self.error = str(exc)


class VaultApp:
    def __init__(self, root=None):
        load_fonts()
        self.root = root or Window()
        self.root.setWindowTitle('Lockfin · Companion')
        self.root.resize(440, 540)
        self.root.setMinimumSize(400, 480)
        screen = QApplication.primaryScreen()
        if screen and screen.availableGeometry().height() < 630:
            self.root.resize(440, max(480, screen.availableGeometry().height() - 90))
        self.root.can_close = self.discard_changes
        self.records, self.candidates = [], []
        self.master = self.path = self.original = None
        self.dirty = False
        if os.getenv('LOCKFIN_DATA_DIR'):
            self.private_dir = Path(os.environ['LOCKFIN_DATA_DIR'])
        elif getattr(sys, 'frozen', False):
            self.private_dir = Path(QStandardPaths.writableLocation(
                QStandardPaths.StandardLocation.AppDataLocation)) / 'vaults'
        else:
            self.private_dir = PRIVATE
        self.private_dir.mkdir(parents=True, exist_ok=True)
        self.root.setStyleSheet('''
            QMainWindow{background:transparent;}
            QWidget{background:transparent;color:#ff9722;}
            QDialog,QMessageBox{background:#140900;}
            QLineEdit{background:#0b0500;color:#ff9722;border:1px solid #9e5823;padding:8px;border-radius:3px;selection-background-color:#76380b;}
            QPushButton{padding:8px 10px;border:1px solid #ff9722;background:#241000;color:#ff9722;border-radius:3px;}
            QPushButton#primary{background:#ff9722;color:#130800;}
            QPushButton#primary:hover{background:#fe8a2c;}
            QPushButton:disabled{color:#76380b;background:#140900;border-color:#491d00;}
            QTableWidget{background:#0b0500;color:#ff9722;alternate-background-color:#1c0c00;border:1px solid #9e5823;gridline-color:#491d00;selection-background-color:#491d00;}
            QHeaderView::section{background:#3a1f10;color:#ff9722;padding:5px;border:0;}
            QCheckBox{color:#ff9722;}
            QLineEdit,QHeaderView,QToolButton,QDialogButtonBox{
                font-family:"HaxrCorp 4089";font-size:32px;
            }
            QTableWidget::indicator{width:10px;height:10px;border:1px solid #9e5823;background:#140900;}
            QTableWidget::indicator:checked{background:#ff9722;border:2px solid #ff9722;}
        ''')
        app_font = QFont('HaxrCorp 4089'); app_font.setPixelSize(32)
        self.root.setFont(app_font)
        frame = ChromeFrame(); frame_layout = QVBoxLayout(frame)
        frame_layout.setContentsMargins(12, 8, 12, 12); frame_layout.setSpacing(8)
        frame_layout.addWidget(TitleBar(self.root))
        outer = GridPanel(); frame_layout.addWidget(outer, 1)
        layout = QVBoxLayout(outer)
        layout.setContentsMargins(16, 12, 16, 12); layout.setSpacing(6)
        layout.addWidget(label('Lockfin', 40, family='Born2bSportyV2'))
        layout.addWidget(label('Your accounts. Ready for your Flipper.', 32, '#9e5823'))
        self.stack = QStackedWidget()
        self.stack.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Ignored)
        landing = QWidget(); landing_layout = QVBoxLayout(landing)
        landing_layout.setContentsMargins(0, 12, 0, 8)
        landing_layout.setSpacing(0)
        self.drop = DropZone(); self.drop.file_dropped.connect(self.load_file)
        self.drop.picker_requested.connect(self.choose_file)
        landing_layout.addWidget(self.drop, 1)
        landing_layout.addSpacing(16)
        device_actions = QVBoxLayout()
        device_actions.setContentsMargins(0, 0, 0, 0)
        device_actions.setSpacing(8)
        landing_layout.addLayout(device_actions)
        self.pull = DevicePull(self.private_dir, self.root)
        self.device_id = None
        self.last_attached = None
        self.mounted = None
        self.adding = False
        self.transferring = False
        self.pull.inspected.connect(self.device_inspected)
        self.pull.notice.connect(self.sync_notice)
        self.pull.received.connect(self.sync_received)
        self.sync_path = None
        self.sync_button = action_button('Sync from Flipper')
        self.sync_button.clicked.connect(self.sync_device)
        device_actions.addWidget(self.sync_button)
        self.open_backup = action_button('Open device vault')
        self.open_backup.clicked.connect(self.open_device_vault)
        self.open_backup.hide()
        device_actions.addWidget(self.open_backup)
        self.stack.addWidget(landing)
        preview = QWidget(); preview_layout = QVBoxLayout(preview)
        preview_layout.setContentsMargins(0, 0, 0, 0)
        self.source = label('', 16, '#ce8647', 'ProggySquareTT'); preview_layout.addWidget(self.source)
        self.search = QLineEdit(); self.search.setPlaceholderText('Filter accounts…')
        self.search.textChanged.connect(self.filter_rows); preview_layout.addWidget(self.search)
        self.table = AccountTable(0, 3)
        data_font = QFont(QApplication.font()); data_font.setPixelSize(15)
        self.table.setFont(data_font)
        self.table.setSelectionMode(QTableWidget.SelectionMode.ExtendedSelection)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setDragEnabled(False)
        self.table.setItemDelegate(AccountDelegate(self.table))
        self.table.selectionModel().selectionChanged.connect(self.rows_selected)
        self.table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.table.row_toggled.connect(self.toggle_row)
        self.table.setHorizontalHeaderLabels(['', 'Account', 'Username'])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 26)
        self.table.verticalHeader().setDefaultSectionSize(30)
        for column in (1, 2):
            self.table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().hide()
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.itemChanged.connect(self.selection_changed)
        preview_layout.addWidget(self.table, 1)
        self.import_button = ImportButton('Add more passwords')
        self.import_button.setFont(pixel_font())
        self.import_button.setFixedHeight(40)
        self.import_button.setAcceptDrops(True)
        self.import_button.clicked.connect(lambda: self.add_export(self.pick_path()))
        self.import_button.file_dropped.connect(self.add_export)
        preview_layout.addWidget(self.import_button)
        options = QHBoxLayout()
        options.setSpacing(4)
        self.selection_buttons = []
        for text, command in [('Select visible', self.mark_visible), ('Clear', self.clear_selection),
                              ('Back', self.back)]:
            button = action_button(text); button.clicked.connect(command)
            button.setFixedHeight(40)
            button.setStyleSheet("QPushButton { padding: 8px 7px; }")
            button.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
            options.addWidget(button, 1)
            if text != 'Back':
                self.selection_buttons.append(button)
        preview_layout.addLayout(options)
        self.save_button = action_button('Save encrypted vault')
        self.save_button.setObjectName('primary'); self.save_button.clicked.connect(self.save)
        preview_layout.addWidget(self.save_button)
        self.change_key = action_button('Change vault password')
        self.change_key.clicked.connect(self.change_password)
        preview_layout.addWidget(self.change_key)
        self.stack.addWidget(preview)
        layout.addWidget(self.stack, 1)
        status = label('LOCAL ENCRYPTION  ·  NO CLOUD', 16, '#ce8647', 'ProggySquareTT')
        self.status = SimpleNamespace(set=status.setText)
        footer = QHBoxLayout(); footer.addWidget(status, 1)
        footer.addWidget(QSizeGrip(self.root))
        layout.addLayout(footer)
        self.root.setCentralWidget(frame)
        self.refresh()

    def watch_device(self):
        attached = device.connected_device()
        identity = attached.serial_number if attached else None
        if identity != self.last_attached and not self.transferring and not self.pull.isRunning():
            self.last_attached = identity
            self.device_id = None
            if identity:
                self.sync_device()

    def sync_device(self):
        if not self.transferring and not self.pull.isRunning():
            self.device_id = None
            self.pull.start()

    def device_inspected(self, identity, firmware, installed):
        attached = device.connected_device()
        if not attached or attached.serial_number != identity:
            return
        self.device_id = identity
        if installed:
            return
        if device_choice(self.root, 'Install Lockfin on this Flipper?', ['Install', 'Not now']) != 1:
            return
        if self.device_operation('Installing Lockfin', device.install, identity, firmware):
            self.status.set('Lockfin installed on the Flipper.')

    def device_operation(self, title, function, *args):
        progress = TransferDialog(self.root, Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint |
                                  Qt.WindowType.NoDropShadowWindowHint)
        progress.setStyleSheet("QDialog { background: transparent; }")
        progress.setWindowTitle(title)
        progress.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        frame = ChromeFrame()
        shell = QVBoxLayout(progress)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSizeConstraint(QLayout.SizeConstraint.SetFixedSize)
        shell.addWidget(frame)
        layout = QHBoxLayout(frame)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(10)
        caption = label(title, 32, crisp=True)
        caption.setWordWrap(False)
        layout.addWidget(caption)
        layout.addWidget(TransferDots(), 0, Qt.AlignmentFlag.AlignVCenter)
        task = DeviceOperation(function, args, progress)
        task.finished.connect(progress.accept)
        self.transferring = True
        task.start()
        progress.exec()
        task.wait()
        self.transferring = False
        error = task.error
        progress.deleteLater()
        if error:
            self.error(error)
        return error is None

    def sync_notice(self, message):
        if self.stack.currentIndex() == 0:
            self.status.set(message)

    def sync_received(self, identity, filename):
        self.sync_identity = identity
        self.sync_path = Path(filename)
        self.open_backup.show()
        self.sync_notice('Encrypted device backup is ready.')

    def open_device_vault(self):
        if self.sync_path and self.load_file(self.sync_path):
            self.mounted = SimpleNamespace(records=list(self.candidates), identity=self.sync_identity,
                                           digest=md5(self.original).hexdigest().encode())
            self.source.setText(f'Device vault · {len(self.candidates)} accounts')
            self.refresh()
            # Keep the downloaded snapshot immutable; device edits use its digest.
            self.path = self.original = None

    def error(self, message, detail=None):
        if detail is None:
            QMessageBox.warning(self.root, 'Lockfin', str(message))
        else:
            device_choice(self.root, message, ['OK'], detail=detail)

    def pick_path(self, saving=False):
        if not saving:
            patterns = ' '.join('*' + extension for extension in sorted(importers.EXTENSIONS))
            filename, _ = QFileDialog.getOpenFileName(
                self.root, 'Open a password export',
                QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation),
                f'Password exports ({patterns})')
            return filename or None

        title = 'Save encrypted vault'
        documents = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DocumentsLocation)
        folder = Path(os.environ['LOCKFIN_DATA_DIR']) if os.getenv('LOCKFIN_DATA_DIR') else Path(documents or Path.home())/'Lockfin'
        try:
            folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError:
            folder = Path.home()
        filename, _ = QFileDialog.getSaveFileName(
            self.root, title, str(folder / 'vault.lmv'), 'Lockfin vault (*.lmv)')
        return filename or None

    def choose_file(self):
        filename = self.pick_path()
        if filename:
            self.load_file(filename)

    def change_password(self):
        # Rekey the complete saved vault, independently of preview selection.
        if self.master is None:
            return
        dialog = MasterDialog(self.root, confirm=True)
        dialog.setWindowTitle('Change vault password')
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            if self.mounted is not None:
                if self.device_id != self.mounted.identity:
                    self.error("Reconnect and sync the original Flipper with supported firmware.")
                    return
                target = self.mounted
                blob = vault.seal(target.records, dialog.result_key)
                if not self.device_operation('Changing vault password', device.save_vault,
                                             target.identity, blob, target.digest):
                    return
                target.digest = md5(blob).hexdigest().encode()
                self.sync_path = None
                self.open_backup.hide()
                self.sync_device()
                message = 'Password changed on the Flipper.'
            elif self.original is not None and self.path is not None:
                records = vault.unseal(self.original, self.master)
                blob = vault.seal(records, dialog.result_key)
                vault.atomic_write(self.path, blob, replace=True, previous=self.original)
                self.original = blob
                message = 'Password changed for this PC vault.'
            else:
                self.dirty = True
                message = 'New password set. Save a working copy to apply it.'
            self.master = dialog.result_key
            self.status.set(message)
        except (OSError, vault.VaultError) as exc:
            self.error(exc)

    def load_file(self, filename):
        if not self.discard_changes():
            return
        path = Path(filename)
        master = original = saved_path = None
        try:
            if path.suffix.lower() == '.lmv':
                dialog = MasterDialog(self.root)
                if dialog.exec() != QDialog.DialogCode.Accepted:
                    return
                master = dialog.result_key
                original = vault.read_blob(path)
                candidates = vault.unseal(original, master)
                saved_path = path
                description = 'Encrypted vault'
            else:
                report = self.read_export(path)
                if report is None:
                    return
                candidates = report.records
                omitted = report.without_password + report.non_logins + report.invalid + report.duplicates
                description = f'{report.source_format} · {omitted} skipped'
        except (OSError, vault.VaultError) as exc:
            self.error(exc); return
        self.mounted = None
        self.adding = False
        self.master, self.original, self.path = master, original, saved_path
        self.show_candidates(candidates, f'{path.name}\n{description} · {len(candidates)} accounts\nClick a row to include its username and password.')
        return True

    def read_export(self, path):
        try:
            return importers.read_import(path)
        except importers.ExportPasswordRequired:
            password, accepted = QInputDialog.getText(self.root, 'Bitwarden export',
                'Export password', QLineEdit.EchoMode.Password, flags=Qt.WindowType.FramelessWindowHint)
            return importers.read_import(path, password) if accepted else None

    def add_export(self, filename):
        if not filename or self.mounted is None:
            return
        if Path(filename).suffix.lower() == '.lmv':
            self.error('Choose a password export to add accounts.')
            return
        try:
            report = self.read_export(Path(filename))
            if report is None:
                return
            existing = {tuple(record) for record in self.mounted.records}
            candidates = [record for record in report.records if tuple(record) not in existing]
        except (OSError, vault.VaultError) as exc:
            self.error(exc)
            return
        if not candidates:
            self.status.set('No new accounts in this export.')
            return
        self.adding = True
        self.show_candidates(candidates, f'{Path(filename).name} · Select accounts to add.\n'
                             f'{len(self.mounted.records)} existing accounts will be kept.')

    def show_candidates(self, candidates, description):
        self.table.blockSignals(True); self.table.clearSelection(); self.table.blockSignals(False)
        self.candidates = candidates
        self.dirty = False
        self.source.setText(description)
        self.search.clear()
        self.table.blockSignals(True); self.table.setRowCount(len(candidates))
        for row, fields in enumerate(candidates):
            checkbox = QTableWidgetItem()
            checkbox.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsSelectable)
            checkbox.setCheckState(Qt.CheckState.Unchecked)
            self.table.setItem(row, 0, checkbox)
            for column, value in enumerate(fields[:2], 1):
                item = QTableWidgetItem(value)
                if column == 1 and isinstance(fields, vault.FavoriteLogin):
                    item.setText('★ ' + value)
                self.table.setItem(row, column, item)
        self.table.blockSignals(False)
        self.filter_rows(self.search.text())
        self.records = []
        self.stack.setCurrentIndex(1)
        self.refresh()

    def selection_limit(self):
        return vault.MAX_LOGINS - (len(self.mounted.records) if self.adding else 0)

    def rows_selected(self, selected, deselected):
        if self.table.signalsBlocked() or (self.mounted is not None and not self.adding):
            return
        rows = {index.row() for index in self.table.selectionModel().selectedRows()}
        previous = {row for row in range(len(self.candidates))
                    if self.table.item(row, 0) is not None and
                    self.table.item(row, 0).checkState() == Qt.CheckState.Checked}
        limited = len(rows) > self.selection_limit()
        if limited:
            retained = rows & previous
            rows = retained | set(sorted(rows-previous)[:self.selection_limit()-len(retained)])
        self.table.blockSignals(True)
        for row in range(len(self.candidates)):
            self.table.item(row, 0).setCheckState(Qt.CheckState.Checked if row in rows
                                                else Qt.CheckState.Unchecked)
        self.table.blockSignals(False)
        self.records = [self.candidates[row] for row in sorted(rows)]
        self.dirty = True; self.refresh()
        if limited:
            self.status.set(f'{self.selection_limit()} selected (vault limit). Uncheck rows to include others.')

    def toggle_row(self, row):
        if self.mounted is not None and not self.adding:
            return
        item = self.table.item(row, 0)
        item.setCheckState(Qt.CheckState.Unchecked if item.checkState() == Qt.CheckState.Checked
                           else Qt.CheckState.Checked)

    def selection_changed(self, item):
        if item.column() != 0:
            return
        records = [self.candidates[row] for row in range(len(self.candidates))
                   if self.table.item(row, 0).checkState() == Qt.CheckState.Checked]
        if len(records) > self.selection_limit():
            self.table.blockSignals(True); item.setCheckState(Qt.CheckState.Unchecked)
            self.table.blockSignals(False)
            self.error(f'This vault supports {self.selection_limit()} accounts. Uncheck an account to choose another.'); return
        self.records, self.dirty = records, True
        self.refresh()

    def refresh(self):
        browsing = self.mounted is not None and not self.adding
        self.import_button.setVisible(browsing)
        self.table.setSelectionMode(QTableWidget.SelectionMode.NoSelection if browsing else
                                    QTableWidget.SelectionMode.ExtendedSelection)
        self.table.setColumnHidden(0, browsing)
        self.save_button.setVisible(not browsing)
        self.save_button.setText('Save additions to Flipper' if self.adding else 'Save encrypted vault')
        self.change_key.setVisible(self.master is not None and not self.adding)
        for button in self.selection_buttons:
            button.setVisible(not browsing)
        self.save_button.setEnabled(bool(self.candidates))
        self.save_button.setToolTip('Choose accounts, set a vault password, then choose where to save.')
        self.table.blockSignals(True)
        for row in range(len(self.candidates)):
            checked = self.table.item(row, 0).checkState() == Qt.CheckState.Checked
            color = QColor('#491d00' if checked else ('#1c0c00' if row % 2 else '#0b0500'))
            for column in range(3):
                self.table.item(row, column).setBackground(color)
        self.table.blockSignals(False)
        selection = QItemSelection()
        for row in range(len(self.candidates)):
            if self.table.item(row, 0).checkState() == Qt.CheckState.Checked:
                selection.select(self.table.model().index(row, 0), self.table.model().index(row, 2))
        model = self.table.selectionModel(); model.blockSignals(True)
        model.select(selection, QItemSelectionModel.SelectionFlag.ClearAndSelect |
                     QItemSelectionModel.SelectionFlag.Rows)
        model.blockSignals(False)
        if browsing:
            self.status.set('Drop a file on Add more passwords or click to browse.')
            return
        self.status.set(f'{len(self.records)} / {self.selection_limit()} selected · username + password included'
                        if self.records else (f'0 / {self.selection_limit()} selected · click a row or Select visible'
                        if self.candidates else 'LOCAL ENCRYPTION  ·  NO CLOUD'))

    def filter_rows(self, text):
        query = text.casefold()
        for row, record in enumerate(self.candidates):
            self.table.setRowHidden(row, query not in (record[0]+' '+record[1]).casefold())

    def mark_visible(self):
        rows = [r for r in range(len(self.candidates)) if not self.table.isRowHidden(r)]
        checked = {r for r in range(len(self.candidates))
                   if self.table.item(r, 0).checkState() == Qt.CheckState.Checked}
        available = [row for row in rows if row not in checked]
        selected = available[:max(0, self.selection_limit()-len(checked))]
        self.table.blockSignals(True)
        for row in selected:
            self.table.item(row, 0).setCheckState(Qt.CheckState.Checked)
        self.table.blockSignals(False)
        self.records = [self.candidates[r] for r in sorted(checked.union(selected))]
        self.dirty = True; self.refresh()
        if len(selected) < len(available):
            self.status.set(f'{self.selection_limit()} selected (vault limit). Filter or uncheck rows to choose different accounts.')

    def clear_selection(self):
        self.table.blockSignals(True)
        for row in range(len(self.candidates)):
            self.table.item(row, 0).setCheckState(Qt.CheckState.Unchecked)
        self.table.blockSignals(False)
        self.records, self.dirty = [], True; self.refresh()

    def save(self):
        if not self.records:
            self.error('Select accounts before saving',
                       'Click an account row or use Select visible. Each account includes its username and password.')
            return False
        if getattr(self, 'adding', False):
            if self.device_id != self.mounted.identity:
                self.error("Reconnect and sync the original Flipper with supported firmware.")
                return False
            target = self.mounted
            combined = target.records + self.records
            try:
                blob = vault.seal(combined, self.master)
            except vault.VaultError as exc:
                self.error(exc)
                return False
            if not self.device_operation('Saving encrypted vault', device.save_vault,
                                         target.identity, blob, target.digest):
                return False
            target.records = combined
            target.digest = md5(blob).hexdigest().encode()
            self.adding = False
            self.show_candidates(combined, f'Device vault · {len(combined)} accounts')
            self.sync_path = None
            self.open_backup.hide()
            self.sync_device()
            return True
        master = self.master
        if master is None:
            dialog = MasterDialog(self.root, confirm=True)
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return False
            master = dialog.result_key
        path = self.path
        if path is None and getattr(self, 'device_id', None):
            attached = device.connected_device()
            if attached and attached.serial_number == self.device_id:
                choice = device_choice(self.root, 'Save encrypted vault', [
                    'Save to Flipper', 'Save to computer', 'Cancel'])
                if choice == 1:
                    try:
                        with device.session(self.device_id) as port:
                            previous = device.vault_digest(port)
                        if previous is not None and device_choice(
                                self.root, 'Replace the vault on this Flipper?',
                                ['Cancel', 'Replace encrypted vault']) != 2:
                            return False
                        blob = vault.seal(self.records, master)
                    except (ValueError, OSError, vault.VaultError) as exc:
                        self.error(exc)
                        return False
                    if not self.device_operation('Saving encrypted vault', device.save_vault,
                                                 self.device_id, blob, previous):
                        return False
                    self.master, self.dirty = master, False
                    self.refresh()
                    self.status.set('Saved to Flipper: /ext/apps_data/lockfin/vault.lmv')
                    return True
                if choice != 2:
                    return False
        if path is None:
            filename = self.pick_path(saving=True)
            if not filename:
                return False
            path = Path(filename)
            if path.suffix.lower() != '.lmv':
                path = Path(str(path)+'.lmv')
        try:
            blob = vault.seal(self.records, master)
            vault.atomic_write(path, blob, replace=self.original is not None, previous=self.original)
        except (OSError, vault.VaultError) as exc:
            self.error(exc); return False
        self.master, self.path, self.original, self.dirty = master, path, blob, False
        self.refresh()
        self.status.set(f'Saved encrypted: {len(self.records)} accounts — {path.name}')
        self.saved(path)
        return True

    def saved(self, path):
        dialog = QDialog(self.root, Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        dialog.setWindowTitle('Vault saved')
        dialog.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        shell = QVBoxLayout(dialog)
        shell.setContentsMargins(0, 0, 0, 0)
        frame = ChromeFrame()
        shell.addWidget(frame)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.addWidget(label('Encrypted vault saved', 28, family='Born2bSportyV2'))
        for text in (str(path), 'Copy to /ext/apps_data/lockfin/vault.lmv'):
            line = label(text, 16, family='ProggySquareTT')
            line.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            layout.addWidget(line)
        row = QHBoxLayout()
        folder = action_button('Open folder')
        folder.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(path.parent))))
        row.addWidget(folder)
        ok = action_button('OK')
        ok.clicked.connect(dialog.accept)
        row.addWidget(ok)
        layout.addLayout(row)
        dialog.resize(455, dialog.sizeHint().height())
        dialog.exec()
        dialog.deleteLater()

    def discard_changes(self):
        if not self.dirty:
            return True
        dialog = QDialog(self.root, Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        dialog.setWindowTitle('Unsaved changes')
        dialog.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        shell = QVBoxLayout(dialog)
        shell.setContentsMargins(0, 0, 0, 0)
        frame = ChromeFrame()
        shell.addWidget(frame)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(16, 14, 16, 14)
        prompt = label('Save changes before continuing?')
        prompt.setFont(pixel_font())
        prompt.setWordWrap(False)
        prompt.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dialog.setMinimumWidth(max(368, prompt.sizeHint().width()+48))
        layout.addWidget(prompt)
        actions = QHBoxLayout()
        layout.addLayout(actions)
        for caption, result in [('Save', QMessageBox.StandardButton.Save),
                                ('Discard', QMessageBox.StandardButton.Discard),
                                ('Cancel', QMessageBox.StandardButton.Cancel)]:
            button = action_button(caption)
            button.clicked.connect(lambda checked=False, code=result: dialog.done(code.value))
            actions.addWidget(button, 1)
        button.setDefault(True)
        button.setFocus()
        result = dialog.exec()
        dialog.deleteLater()
        if result == QMessageBox.StandardButton.Save.value:
            return self.save()
        return result == QMessageBox.StandardButton.Discard.value

    def back(self):
        was_adding = self.adding
        if not self.discard_changes():
            return
        if was_adding:
            self.adding = False
            self.show_candidates(self.mounted.records, f'Device vault · {len(self.mounted.records)} accounts')
            return
        self.table.blockSignals(True)
        self.records, self.candidates = [], []
        self.master = self.path = self.original = self.mounted = None
        self.adding = False
        self.dirty = False
        self.table.setRowCount(0)
        self.table.blockSignals(False)
        self.stack.setCurrentIndex(0); self.refresh()


def main():
    parser = argparse.ArgumentParser(description='Lockfin companion')
    parser.add_argument('--smoke-test', action='store_true')
    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args()
    # The Linux bundle ships the desktop portal plugin. KDE's host Qt
    # integration plugin is not part of the bundle.
    if (sys.platform.startswith('linux') and getattr(sys, 'frozen', False)
            and os.getenv('DBUS_SESSION_BUS_ADDRESS')
            and os.getenv('QT_QPA_PLATFORMTHEME', '').lower() in ('', 'kde')):
        os.environ['QT_QPA_PLATFORMTHEME'] = 'xdgdesktopportal'
    qt = QApplication(sys.argv)
    qt.setApplicationName('Lockfin')
    qt.setApplicationVersion(VERSION)
    qt.setDesktopFileName('lockfin')
    icon = PROJECT / 'assets/lockfin.svg'
    if icon.is_file():
        qt.setWindowIcon(QIcon(str(icon)))
    if args.smoke_test:
        with tempfile.TemporaryDirectory(prefix='lockfin-smoke-') as directory:
            os.environ['LOCKFIN_DATA_DIR'] = directory
            app = VaultApp(); app.root.show(); qt.processEvents()
            assert app.root.windowFlags() & Qt.WindowType.FramelessWindowHint
            assert app.root.findChild(GridPanel).animation.isActive()
            assert app.root.width() == 440
            assert app.root.height() == 540
            print('LOCKFIN_SMOKE_OK: frameless 440x540, original qFlipper scanline, bundled fonts.')
            app.root.close(); qt.processEvents()
        return 0
    app = VaultApp(); app.root.show()
    watcher = QTimer(app.root)
    watcher.timeout.connect(app.watch_device)
    watcher.start(2500)
    QTimer.singleShot(0, app.watch_device)
    return qt.exec()


if __name__ == '__main__':
    raise SystemExit(main())
