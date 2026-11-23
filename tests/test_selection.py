"""Real Qt input and save regressions; synthetic credentials only, no screenshots."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from PySide6.QtCore import Qt, QEvent, QPoint
from PySide6.QtGui import QFontInfo, QMouseEvent
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication, QDialog, QPushButton

import desktop
import vault


class SelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt = QApplication.instance() or QApplication([])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=desktop.PROJECT / '.tools')
        self.addCleanup(self.temp.cleanup)
        self.environment = patch.dict(os.environ, {'LOCKFIN_DATA_DIR': self.temp.name})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.app = desktop.VaultApp()
        self.app.root.show()
        self.qt.processEvents()

    def tearDown(self):
        self.app.dirty = False
        self.app.root.close()
        self.app.root.deleteLater()
        self.qt.processEvents()

    def load(self, count):
        records = [{'name': f'Demo {i:03}', 'username': f'dummy{i}',
                    'password': f'FictitiousOnly{i}!'} for i in range(count)]
        path = Path(self.temp.name) / 'synthetic.json'
        path.write_text(json.dumps(records))
        self.app.load_file(str(path))
        self.qt.processEvents()

    def test_clicking_any_column_selects_whole_credential(self):
        self.load(vault.MAX_LOGINS + 1)
        for column in (0, 1, 2):
            rect = self.app.table.visualItemRect(self.app.table.item(0, column))
            QTest.mouseClick(self.app.table.viewport(), Qt.MouseButton.LeftButton, pos=rect.center())
            self.assertEqual(self.app.records, [self.app.candidates[0]])
            self.assertEqual(self.app.table.item(0, 1).background(),
                             self.app.table.item(0, 2).background())
            QTest.keyClick(self.app.table, Qt.Key.Key_Space)
            self.assertEqual(self.app.records, [])

    def test_select_visible_fills_capacity_and_preserves_hidden_accounts(self):
        last = vault.MAX_LOGINS + 4
        self.load(last + 1)
        self.app.mark_visible()
        self.assertEqual(len(self.app.records), vault.MAX_LOGINS)
        self.app.toggle_row(0)
        self.app.search.setText(f'Demo {last:03}')
        self.app.mark_visible()
        self.assertEqual(len(self.app.records), vault.MAX_LOGINS)
        self.assertIn(self.app.candidates[last], self.app.records)
        self.assertNotIn(self.app.candidates[0], self.app.records)

    def test_save_without_selection_explains_required_action(self):
        self.load(vault.MAX_LOGINS + 1)
        self.assertTrue(self.app.save_button.isEnabled())
        with patch.object(self.app, 'error') as error:
            self.assertFalse(self.app.save())
            self.assertEqual(error.call_args.args[0], 'Select accounts before saving')
            self.assertIn('Click an account', error.call_args.args[1])

    def test_save_dialog_flow_writes_complete_encrypted_credential(self):
        self.load(1)
        self.assertEqual(self.app.records, [])
        self.assertEqual(self.app.table.item(0, 0).checkState(), Qt.CheckState.Unchecked)
        self.app.mark_visible()
        target = Path(self.temp.name) / 'result.lmv'
        def accept(dialog):
            dialog.first.setText('FictitiousMaster123!')
            dialog.second.setText('FictitiousMaster123!')
            dialog.validate()
            return QDialog.DialogCode.Accepted
        with patch.object(desktop.MasterDialog, 'exec', accept), \
             patch.object(self.app, 'pick_path', return_value=str(target)), \
             patch.object(self.app, 'saved') as saved:
            self.assertTrue(self.app.save())
            saved.assert_called_once_with(target)
        self.assertEqual(vault.unseal(target.read_bytes(), 'FictitiousMaster123!'),
                         self.app.candidates)

    def test_shift_ctrl_and_mouse_drag_select_complete_rows(self):
        self.app.root.resize(700, 800)
        self.load(vault.MAX_LOGINS + 1)
        table = self.app.table
        def point(row):
            return table.visualItemRect(table.item(row, 1)).center()
        QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton, pos=point(0))
        QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton,
                         Qt.KeyboardModifier.ShiftModifier, pos=point(3))
        self.assertEqual(self.app.records, self.app.candidates[:4])
        QTest.mouseClick(table.viewport(), Qt.MouseButton.LeftButton,
                         Qt.KeyboardModifier.ControlModifier, pos=point(5))
        self.assertEqual(self.app.records, self.app.candidates[:4]+[self.app.candidates[5]])
        self.app.clear_selection()
        QTest.mousePress(table.viewport(), Qt.MouseButton.LeftButton, pos=point(1))
        end = point(4)
        move = QMouseEvent(QEvent.Type.MouseMove, end, table.viewport().mapToGlobal(end),
                          Qt.MouseButton.NoButton, Qt.MouseButton.LeftButton,
                          Qt.KeyboardModifier.NoModifier)
        QApplication.sendEvent(table.viewport(), move)
        QTest.mouseRelease(table.viewport(), Qt.MouseButton.LeftButton, pos=end)
        self.assertEqual(self.app.records, self.app.candidates[1:5])

    def test_transfer_dialog_clips_all_four_corners(self):
        dialog = desktop.TransferDialog(self.app.root, Qt.WindowType.FramelessWindowHint)
        dialog.resize(276, 58)
        dialog.show()
        self.qt.processEvents()
        try:
            rect = dialog.rect()
            mask = dialog.mask()
            self.assertTrue(mask.contains(rect.center()))
            for corner in (rect.topLeft(), rect.topRight(), rect.bottomLeft(), rect.bottomRight()):
                self.assertFalse(mask.contains(corner))
        finally:
            dialog.close()

    def test_frame_buttons_and_password_dialog_geometry(self):
        self.load(1)
        buttons = [b for b in self.app.root.findChildren(QPushButton)
                   if b.text() in ('Select visible', 'Clear', 'Back')]
        self.assertEqual(len(buttons), 3)
        self.assertEqual({b.height() for b in buttons}, {40})
        self.assertLessEqual(max(b.width() for b in buttons)-min(b.width() for b in buttons), 1)
        title = self.app.root.findChild(desktop.TitleBar)
        grid = self.app.root.findChild(desktop.GridPanel)
        self.assertLess(title.mapTo(self.app.root, QPoint(0, title.height())).y(),
                        grid.mapTo(self.app.root, QPoint(0, 0)).y())
        dialog = desktop.MasterDialog(self.app.root, confirm=True)
        dialog.show(); self.qt.processEvents()
        try:
            self.assertTrue(dialog.windowFlags() & Qt.WindowType.FramelessWindowHint)
            self.assertEqual(dialog.first.font().pixelSize(), 18)
            self.assertGreaterEqual(dialog.first.height()-12,
                                    dialog.first.fontMetrics().boundingRect('••••').height())
            dialog.first.setText('short')
            with patch.object(desktop.QMessageBox, 'warning') as warning:
                dialog.validate()
                warning.assert_not_called()
            self.assertTrue(dialog.validation_error.isVisible())
            self.assertNotIn('ASCII', dialog.validation_error.text())
        finally:
            dialog.reject(); dialog.deleteLater(); self.qt.processEvents()

    def test_fixed_grid_hidden_scrollbars_and_control_fonts(self):
        grid = self.app.root.findChild(desktop.GridPanel)
        grid.resize(440, 540)
        self.assertEqual(grid.grid_step, 27)
        grid.resize(850, 600)
        self.assertEqual(grid.grid_step, 27)
        self.assertEqual(self.app.table.verticalScrollBarPolicy(), Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.assertEqual(self.app.table.horizontalScrollBarPolicy(), Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.assertEqual(QFontInfo(self.app.search.font()).family().casefold(), 'haxrcorp 4089')
        self.assertEqual(QFontInfo(self.app.save_button.font()).family().casefold(), 'haxrcorp 4089')
        self.assertNotEqual(QFontInfo(self.app.table.font()).family().casefold(), 'haxrcorp 4089')
        self.assertEqual(self.app.search.font().pixelSize(), 32)
        self.assertEqual(QFontInfo(self.app.source.font()).family(), 'ProggySquareTT')


if __name__ == '__main__':
    unittest.main()
