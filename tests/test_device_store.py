"""Run the real device serializer/transaction code with simulated storage and AES-GCM."""
import ctypes
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import vault

ROOT = Path(__file__).resolve().parents[1]
U8 = ctypes.POINTER(ctypes.c_uint8)
ENCRYPT = ctypes.CFUNCTYPE(ctypes.c_int,U8,U8,U8,ctypes.c_size_t,U8,U8,ctypes.c_size_t,U8)


class DeviceStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_dir = tempfile.TemporaryDirectory(dir=ROOT/'.tools')
        source = (ROOT/'login_manager.c').read_text()
        body = source[source.index('static void lm_put_le32('):source.index('static uint8_t lm_random_below(')]
        def section(start, end):
            return source[source.index(start):source.index(end, source.index(start))]
        types = section('#define LM_HEADER_SIZE', 'typedef enum {')
        loader = section('static void lm_free_login', 'typedef struct {\n    uint32_t percent;')
        loader += section('static VaultState lm_load(', 'typedef struct {')
        prefix = r''' 
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
/* REAL_TYPES */
#define LM_VAULT_PATH "vault.lmv"
#define LM_TEMP_PATH ".vault.lmv.tmp"
#define LM_BACKUP_PATH "vault.lmv.bak"
#define EXT_PATH(x) x
#define RECORD_STORAGE "storage"
#define FSAM_READ 1
#define FSAM_WRITE 2
#define FSOM_OPEN_EXISTING 1
#define FSOM_CREATE_ALWAYS 2
#define FSE_OK 0
#define FuriHalCryptoGCMStateOk 0
#define furi_check(x) assert(x)
typedef void Gui;
#define furi_mutex_acquire(a,b) ((void)0)
#define furi_mutex_release(a) ((void)0)
static void lm_notice(Gui* gui,const char* msg){(void)gui;(void)msg;}
typedef enum {VaultReady,VaultCryptoError,VaultBadFormat,VaultMissing,VaultBadPassword,VaultInteropError} VaultState;
typedef int FuriHalCryptoGCMState;
#define FuriHalCryptoGCMStateAuthFailure 1
typedef struct {StoredLogin* logins;uint8_t* loaded_data;size_t loaded_size,count,capacity,invalid,favorites,selected,scroll;int mutex;bool session_key_ready,has_saved;uint32_t rounds;uint8_t salt[16],session_key[32],saved_tag[16];} LoginManager;
typedef struct {int unused;} Storage;
typedef struct {FILE* fp;} File;
static Storage fs;
static int fail_sync,fail_rename;
static unsigned nonce_counter;
typedef int (*Encrypt)(const uint8_t*,const uint8_t*,const uint8_t*,size_t,const uint8_t*,uint8_t*,size_t,uint8_t*);
static Encrypt encrypt_callback, decrypt_callback;
#define furi_hal_crypto_gcm_decrypt_and_verify decrypt_callback
static bool lm_derive_key(const char* m,const uint8_t* s,uint32_t n,uint8_t* k){(void)m;(void)s;(void)n;(void)k;return false;}
static bool lm_crypto_compatible(void){return true;}
static void lm_clear(void* p,size_t n){volatile uint8_t* b=p;while(n--)*b++=0;}
static size_t memmgr_get_free_heap(void){return 1024*1024;}
static void furi_hal_random_fill_buf(uint8_t* p,uint32_t n){for(uint32_t i=0;i<n;i++)p[i]=(uint8_t)++nonce_counter;}
static int furi_hal_crypto_gcm_encrypt_and_tag(const uint8_t* k,const uint8_t* iv,const uint8_t* aad,size_t an,const uint8_t* in,uint8_t* out,size_t n,uint8_t* tag){return encrypt_callback(k,iv,aad,an,in,out,n,tag);}
static Storage* furi_record_open(const char* n){(void)n;return &fs;}
static void furi_record_close(const char* n){(void)n;}
static File* storage_file_alloc(Storage* s){(void)s;return calloc(1,sizeof(File));}
static bool storage_file_open(File* f,const char* p,int access,int mode){(void)mode;f->fp=fopen(p,access==FSAM_READ?"rb":"wb");return f->fp!=NULL;}
static void storage_file_close(File* f){fclose(f->fp);f->fp=NULL;}
static void storage_file_free(File* f){free(f);}
static bool storage_file_exists(Storage* s,const char* p){(void)s;return access(p,F_OK)==0;}
static size_t storage_file_read(File* f,void* p,size_t n){return fread(p,1,n,f->fp);}
static size_t storage_file_write(File* f,const void* p,size_t n){return fwrite(p,1,n,f->fp);}
static uint64_t storage_file_size(File* f){long p=ftell(f->fp);fseek(f->fp,0,SEEK_END);long n=ftell(f->fp);fseek(f->fp,p,SEEK_SET);return n;}
static bool storage_file_seek(File* f,uint32_t o,bool start){return fseek(f->fp,o,start?SEEK_SET:SEEK_CUR)==0;}
static bool storage_file_sync(File* f){return fflush(f->fp)==0&&!fail_sync;}
static bool storage_simply_mkdir(Storage* s,const char* p){(void)s;(void)p;return true;}
static bool storage_simply_remove(Storage* s,const char* p){(void)s;return remove(p)==0||errno==ENOENT;}
static int storage_common_rename(Storage* s,const char* a,const char* b){(void)s;if(fail_rename&&!strcmp(a,LM_TEMP_PATH)){fail_rename=0;return 1;}return rename(a,b)==0?0:1;}
'''
        wrappers = r'''
static LoginManager app;
void host_init(Encrypt callback,const uint8_t* key,const uint8_t* salt){lm_release_logins(&app);memset(&app,0,sizeof(app));app.session_key_ready=true;app.rounds=100000;memcpy(app.session_key,key,32);memcpy(app.salt,salt,16);encrypt_callback=callback;fail_sync=fail_rename=0;nonce_counter=0;}
void host_empty(void){lm_release_logins(&app);app.count=0;}
int host_record(const char* name,const char* user,const char* pass){
    if(strlen(name)>99||strlen(user)>99||strlen(pass)>99)return 0;
    Login draft;
    strcpy(draft.name,name);strcpy(draft.username,user);strcpy(draft.password,pass);
    host_empty();
    if(!lm_reserve(&app,1)||!lm_store_login(&draft,app.logins))return 0;
    app.count=1;return 1;
}
int host_load(Encrypt decrypt,const uint8_t* key,const uint8_t* salt){
    host_empty();decrypt_callback=decrypt;
    return lm_load(&app,NULL,key,salt)==VaultReady ? (int)app.count : -1;
}
void host_fail(int sync,int rename){fail_sync=sync;fail_rename=rename;}
int host_save(void){return lm_save(&app);}
void host_star(size_t row){assert(row<app.count);app.selected=row;lm_toggle_favorite(&app,NULL);}
'''
        c=Path(cls.build_dir.name)/'store.c';so=Path(cls.build_dir.name)/'store.so'
        c.write_text(prefix.replace('/* REAL_TYPES */',types)+loader+body+section('static void lm_move_login(', 'static void lm_manage(')+wrappers)
        result=subprocess.run([shutil.which('cc'),'-shared','-fPIC','-std=c11','-Wall','-Wextra','-Werror',str(c),'-o',str(so)],text=True,capture_output=True)
        if result.returncode:
            raise RuntimeError(result.stderr)
        cls.lib=ctypes.CDLL(str(so))
        cls.lib.host_init.argtypes=[ENCRYPT,U8,U8]
        cls.lib.host_load.argtypes=[ENCRYPT,U8,U8]
        cls.lib.host_record.argtypes=[ctypes.c_char_p]*3
        cls.lib.host_fail.argtypes=[ctypes.c_int,ctypes.c_int]

    @classmethod
    def tearDownClass(cls):
        cls.build_dir.cleanup()

    def setUp(self):
        self.previous=Path.cwd()
        self.directory=tempfile.TemporaryDirectory(dir=ROOT/'.tools')
        self.addCleanup(self.directory.cleanup)
        os.chdir(self.directory.name)
        self.master='OnlyDummyPassword123'
        salt=bytes(range(16))
        key=hashlib.pbkdf2_hmac('sha256',self.master.encode(),salt,100000,32)
        self.key=(ctypes.c_uint8*32).from_buffer_copy(key)
        self.salt=(ctypes.c_uint8*16).from_buffer_copy(salt)
        def encrypt(k,iv,aad,an,plain,out,n,tag):
            result=AESGCM(ctypes.string_at(k,32)).encrypt(ctypes.string_at(iv,12),ctypes.string_at(plain,n),ctypes.string_at(aad,an))
            ctypes.memmove(out,result[:-16],n);ctypes.memmove(tag,result[-16:],16)
            return 0
        self.encrypt=ENCRYPT(encrypt)
        self.lib.host_init(self.encrypt,self.key,self.salt)

    def tearDown(self):
        os.chdir(self.previous)

    def initial(self):
        self.assertEqual(self.lib.host_record(b'Dummy, account',b'user\\name',b'Dummy,\\Password123'),1)
        self.assertEqual(self.lib.host_save(),1)
        return Path('vault.lmv').read_bytes()

    def test_create_edit_and_pc_interoperability(self):
        first=self.initial()
        self.assertEqual(vault.unseal(first,self.master),[['Dummy, account','user\\name','Dummy,\\Password123']])
        self.lib.host_record(b'Edited',b'dummy',b'AnotherDummy123')
        self.assertEqual(self.lib.host_save(),1)
        second=Path('vault.lmv').read_bytes()
        self.assertNotEqual(first,second)
        self.assertEqual(vault.unseal(second,self.master),[['Edited','dummy','AnotherDummy123']])

    def test_500_accounts_companion_to_device_and_back(self):
        def decrypt(k, iv, aad, an, data, out, n, tag):
            try:
                plain = AESGCM(ctypes.string_at(k, 32)).decrypt(
                    ctypes.string_at(iv, 12), ctypes.string_at(data, n) + ctypes.string_at(tag, 16),
                    ctypes.string_at(aad, an))
            except InvalidTag:
                return 1
            ctypes.memmove(out, plain, n)
            return 0

        records = [[f'Site,{i}', f'user{i}@example.test', 'DemoPass' * 3] for i in range(500)]
        blob = vault.seal(records, self.master)
        path = Path('vault.lmv')
        path.write_bytes(blob)
        _, rounds, salt, _, _ = vault.HEADER.unpack_from(blob)
        key = hashlib.pbkdf2_hmac('sha256', self.master.encode(), salt, rounds, 32)
        self.assertEqual(self.lib.host_load(ENCRYPT(decrypt),
                         (ctypes.c_uint8*32).from_buffer_copy(key),
                         (ctypes.c_uint8*16).from_buffer_copy(salt)), 500)
        self.assertEqual(self.lib.host_save(), 1)
        self.assertEqual(vault.unseal(path.read_bytes(), self.master), records)
        self.lib.host_star(499)
        starred_blob = path.read_bytes()
        self.assertEqual(starred_blob[:4], b'LMV2')
        starred = vault.unseal(starred_blob, self.master)
        self.assertIsInstance(starred[0], vault.FavoriteLogin)
        self.assertEqual(starred, [records[-1], *records[:-1]])
        self.assertEqual(self.lib.host_load(ENCRYPT(decrypt),
                         (ctypes.c_uint8*32).from_buffer_copy(key),
                         (ctypes.c_uint8*16).from_buffer_copy(salt)), 500)
        self.lib.host_fail(1, 0)
        self.lib.host_star(0)
        self.assertEqual(path.read_bytes(), starred_blob)
        self.lib.host_fail(0, 0)
        self.assertEqual(self.lib.host_save(), 1)
        self.assertIsInstance(vault.unseal(path.read_bytes(), self.master)[0], vault.FavoriteLogin)
        restored = vault.unseal(vault.seal(starred[:12], 'NewDemoMaster'), 'NewDemoMaster')
        self.assertIsInstance(restored[0], vault.FavoriteLogin)
        self.assertEqual(restored, starred[:12])
        self.lib.host_star(0)
        self.assertEqual(path.read_bytes()[:4], b'LMV1')
        self.assertEqual(vault.unseal(path.read_bytes(), self.master), starred)
        with self.assertRaises(vault.VaultError):
            vault.seal(records + records[:1], self.master)

    def test_delete_last_entry_keeps_valid_encrypted_vault(self):
        self.initial();self.lib.host_empty()
        self.assertEqual(self.lib.host_save(),1)
        self.assertEqual(vault.unseal(Path('vault.lmv').read_bytes(),self.master),[])

    def test_sync_failure_preserves_old_vault(self):
        original=self.initial();self.lib.host_record(b'New',b'dummy',b'NewDummy123')
        self.lib.host_fail(1,0)
        self.assertEqual(self.lib.host_save(),0)
        self.assertEqual(Path('vault.lmv').read_bytes(),original)

    def test_rename_failure_rolls_back(self):
        original=self.initial();self.lib.host_record(b'New',b'dummy',b'NewDummy123')
        self.lib.host_fail(0,1)
        self.assertEqual(self.lib.host_save(),0)
        self.assertEqual(Path('vault.lmv').read_bytes(),original)

    def test_external_file_change_is_not_overwritten(self):
        original=bytearray(self.initial());original[-1]^=1
        Path('vault.lmv').write_bytes(original)
        self.assertEqual(self.lib.host_save(),0)
        self.assertEqual(Path('vault.lmv').read_bytes(),bytes(original))
