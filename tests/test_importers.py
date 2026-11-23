"""Exportaciones ficticias y drag/drop real de Qt, sin capturas."""
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from PySide6.QtCore import QMimeData, QPoint, QPointF, Qt, QUrl
from PySide6.QtGui import QDragEnterEvent, QDropEvent, QFontDatabase
from PySide6.QtWidgets import QApplication, QPushButton
import desktop
import importers
import vault


class ImportTests(unittest.TestCase):
    def setUp(self):
        parent = desktop.PROJECT / '.tools'; parent.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def file(self, name, contents):
        path = self.directory / name
        path.write_text(contents, encoding='utf-8')
        return path

    def test_bitwarden_ignores_passkeys_and_non_logins(self):
        items = [{'type':1,'name':'Demo','login':{'username':'dummy','password':'Ficticia123'}},
                 {'type':1,'name':'Passkey','login':{'username':'dummy','password':None}},
                 {'type':2,'name':'Nota','secureNote':{'type':0}}]
        report = importers.read_import(self.file('demo.json', json.dumps({'items':items})))
        self.assertEqual(report.records,[['Demo','dummy','Ficticia123']])
        self.assertEqual((report.without_password,report.non_logins),(1,1))

    def test_encrypted_manager_json_is_rejected(self):
        with self.assertRaises(vault.VaultError):
            importers.read_import(self.file('demo.json','{"encrypted":true,"data":"dummy"}'))

    def test_csv_preserves_quotes_commas_and_backslashes(self):
        for headings in [('name','username','password'),('Title','User Name','Password'),
                         ('name','login_username','login_password')]:
            output=io.StringIO();writer=csv.writer(output)
            writer.writerow(headings);writer.writerow(['Demo','dummy','p,"a\\ss'])
            report=importers.read_import(self.file('demo.csv',output.getvalue()))
            self.assertEqual(report.records,[['Demo','dummy','p,"a\\ss']])

    def test_xml_ignores_history_and_rejects_entities(self):
        xml='<KeePassFile><Root><Group><Entry><String><Key>Title</Key><Value>Demo</Value></String><String><Key>UserName</Key><Value>dummy</Value></String><String><Key>Password</Key><Value>Ficticia123</Value></String><History><Entry><String><Key>Password</Key><Value>AntiguaFicticia</Value></String></Entry></History></Entry></Group></Root></KeePassFile>'
        self.assertEqual(importers.read_import(self.file('demo.xml',xml)).records,
                         [['Demo','dummy','Ficticia123']])
        with self.assertRaises(vault.VaultError):
            importers.read_import(self.file('demo.xml','<!DOCTYPE test><entries/>'))

    def test_1pux_is_read_without_extracting_secrets(self):
        data={'accounts':[{'vaults':[{'items':[{'overview':{'title':'Demo'},'details':{
            'loginFields':[{'designation':'username','value':'dummy'},
                           {'designation':'password','value':'Ficticia123'}]}}]}]}]}
        path=self.directory/'demo.1pux'
        with zipfile.ZipFile(path,'w') as z:z.writestr('export.data',json.dumps(data))
        self.assertEqual(importers.read_import(path).records,[['Demo','dummy','Ficticia123']])
        self.assertEqual(sorted(p.name for p in self.directory.iterdir()),['demo.1pux'])

    def test_large_export_is_available_for_selection(self):
        items=[{'name':f'Demo{i:03}','username':'dummy','password':'Ficticia123'} for i in range(101)]
        report=importers.read_import(self.file('demo.json',json.dumps(items)))
        self.assertEqual(len(report.records),101)


class DropTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.qt=QApplication.instance() or QApplication([])

    def setUp(self):
        self.app=desktop.VaultApp()
        parent=desktop.PROJECT/'.tools'
        self.temp=tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(self.temp.cleanup)

    def tearDown(self):
        self.app.dirty=False
        self.app.root.close()
        self.app.root.deleteLater()
        self.qt.processEvents()

    def test_native_file_drop_loads_preview_without_file_picker(self):
        path=Path(self.temp.name)/'demo.json'
        path.write_text('[{"name":"Demo","username":"dummy","password":"Ficticia123"}]')
        mime=QMimeData();mime.setUrls([QUrl.fromLocalFile(str(path))])
        enter=QDragEnterEvent(QPoint(20,20),Qt.DropAction.CopyAction,mime,
                             Qt.MouseButton.LeftButton,Qt.KeyboardModifier.NoModifier)
        self.app.drop.dragEnterEvent(enter)
        self.assertTrue(enter.isAccepted())
        drop=QDropEvent(QPointF(20,20),Qt.DropAction.CopyAction,mime,
                       Qt.MouseButton.LeftButton,Qt.KeyboardModifier.NoModifier)
        self.app.drop.dropEvent(drop)
        self.assertTrue(drop.isAccepted())
        self.assertEqual(self.app.stack.currentIndex(),1)
        self.assertEqual(self.app.candidates,[['Demo','dummy','Ficticia123']])
        self.assertEqual(self.app.records,[])
        self.assertIsNone(self.app.master)
        self.assertFalse(self.app.drop.findChildren(QPushButton))
        self.assertIn('Share Tech',QFontDatabase.families())
        self.assertIn('Share Tech Mono',QFontDatabase.families())

    def test_remote_urls_are_rejected(self):
        mime=QMimeData();mime.setUrls([QUrl('https://example.invalid/demo.json')])
        event=QDragEnterEvent(QPoint(20,20),Qt.DropAction.CopyAction,mime,
                             Qt.MouseButton.LeftButton,Qt.KeyboardModifier.NoModifier)
        self.app.drop.dragEnterEvent(event)
        self.assertFalse(event.isAccepted())
