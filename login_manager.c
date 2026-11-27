/*
 * Lockfin 0.26: boveda cifrada y acciones manuales de teclado USB/BLE.
 * Keyboard mapping: US. No automatic Tab, Enter, or credential submission.
 */
#include <furi.h>
#include <furi_hal_bt.h>
#include <bt/bt_service/bt.h>
#include <ble_profile/extra_profiles/hid_profile.h>
#include <stddef.h>
#include <furi_hal_usb.h>
#include <furi_hal_usb_hid.h>
#include <furi_hal_crypto.h>
#include <furi_hal_random.h>
#include <gui/gui.h>
#include <loader/loader.h>
#include <gui/view_port.h>
#include <gui/view_dispatcher.h>
#include <gui/modules/text_input.h>
#include <gui/modules/submenu.h>
#include <gui/modules/variable_item_list.h>
#if __has_include(<assets_icons.h>)
#include <assets_icons.h>
#define LM_HAS_FIRMWARE_ICONS 1
#endif
#include <storage/storage.h>
#include <mbedtls/md.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LM_VAULT_PATH EXT_PATH("apps_data/lockfin/vault.lmv")
#define LM_TEMP_PATH EXT_PATH("apps_data/lockfin/.vault.lmv.tmp")
#define LM_BACKUP_PATH EXT_PATH("apps_data/lockfin/vault.lmv.bak")
#define LM_HEADER_SIZE 40
#define LM_KDF_ITERATIONS 600000u
#define LM_KDF_MAX_ITERATIONS 2000000u
#define LM_MAX_PAYLOAD 32768
#define LM_MASTER_SIZE 64
#define LM_MAX_LOGINS 500
#define LM_FIELD_SIZE 100
#define LM_LINE_SIZE 600
#define LM_VISIBLE_ROWS 2

typedef struct {
    char name[LM_FIELD_SIZE];
    char username[LM_FIELD_SIZE];
    char password[LM_FIELD_SIZE];
} Login;

typedef struct {
    char* name;
    char* username;
    char* password;
    bool owns_data;
} StoredLogin;

static size_t lm_login_bytes(const Login* login) {
    return strlen(login->name) + strlen(login->username) + strlen(login->password) + 3;
}

static void lm_pack_login(const Login* login, StoredLogin* entry, char* data, bool owns_data) {
    entry->name = strcpy(data, login->name);
    entry->username = strcpy(data + strlen(login->name) + 1, login->username);
    entry->password = strcpy(entry->username + strlen(login->username) + 1, login->password);
    entry->owns_data = owns_data;
}

static bool lm_store_login(const Login* draft, StoredLogin* entry) {
    char* data = malloc(lm_login_bytes(draft));
    if(!data) return false;
    lm_pack_login(draft, entry, data, true);
    return true;
}

typedef enum {
    ActionUsername,
    ActionPassword,
    ActionPrevious,
    ActionEnter,
    ActionNext,
    ActionSpace,
    ActionCount,
} Action;

typedef enum {
    StatusReady,
    StatusSent,
    StatusUsbBusy,
    StatusDisconnected,
    StatusNoKeyboard,
    StatusBtWaiting,
    StatusBtUnavailable,
    StatusEmpty,
    StatusUnsupported,
    StatusFailed,
    StatusSaved,
    StatusSaveFailed,
} SendStatus;

typedef enum { KeyboardUsb, KeyboardBle, KeyboardAuto } KeyboardMode;
typedef enum { LayoutUS, LayoutSpain, LayoutLatam, LayoutCount } KeyboardLayout;


typedef enum {
    VaultLocked,
    VaultOpening,
    VaultReady,
    VaultMissing,
    VaultBadFormat,
    VaultBadPassword,
    VaultCryptoError,
    VaultInteropError,
} VaultState;

typedef struct {
    StoredLogin* logins;
    uint8_t* loaded_data;
    size_t loaded_size;
    uint16_t list_order[LM_MAX_LOGINS];
    size_t favorites;
    size_t capacity;
    size_t count;
    size_t invalid;
    size_t selected;
    size_t scroll;
    Action action;
    SendStatus status;
    VaultState vault_state;
    bool details;
    bool shortcuts;
    bool sending;
    bool owns_usb;
    KeyboardMode mode;
    KeyboardLayout layout;
    bool bt_connected;
    Bt* bt;
    FuriHalBleProfileBase* bt_profile;
    BleProfileHidParams bt_params;
    bool session_key_ready;
    bool has_saved;
    uint32_t rounds;
    uint8_t salt[16];
    _Alignas(4) uint8_t session_key[32];
    uint8_t saved_tag[16];
    FuriHalUsbInterface* previous_usb;
    FuriMutex* mutex;
    FuriMessageQueue* events;
    ViewPort* viewport;
} LoginManager;

static void lm_clear(void* pointer, size_t size) {
    volatile unsigned char* bytes = pointer;
    while(size--) *bytes++ = 0;
}

static void lm_free_login(StoredLogin entry) {
    if(!entry.name) return;
    size_t length = (size_t)(entry.password - entry.name) + strlen(entry.password) + 1;
    lm_clear(entry.name, length);
    if(entry.owns_data) free(entry.name);
}

static void lm_release_logins(LoginManager* app) {
    if(app->logins) {
        for(size_t i = 0; i < app->count; ++i) lm_free_login(app->logins[i]);
        free(app->logins);
        app->logins = NULL;
    }
    if(app->loaded_data) {
        lm_clear(app->loaded_data, app->loaded_size);
        free(app->loaded_data);
        app->loaded_data = NULL;
        app->loaded_size = 0;
    }
    app->favorites = 0;
    app->capacity = 0;
}

static bool lm_reserve(LoginManager* app, size_t capacity) {
    if(capacity <= app->capacity) return true;
    if(capacity > LM_MAX_LOGINS) return false;
    size_t bytes = capacity * sizeof(StoredLogin);
    if(memmgr_get_free_heap() < bytes + 8192) return false;
    StoredLogin* replacement = malloc(bytes);
    if(!replacement) return false;
    if(app->count) memcpy(replacement, app->logins, app->count * sizeof(StoredLogin));
    free(app->logins);
    app->logins = replacement;
    app->capacity = capacity;
    return true;
}

/* Reject oversized fields and malformed escapes instead of truncating secrets. */
static bool lm_parse(const char* line, Login* login) {
    char* fields[] = {login->name, login->username, login->password};
    size_t field = 0;
    size_t length = 0;
    bool escaped = false;
    memset(login, 0, sizeof(*login));

    for(const unsigned char* p = (const unsigned char*)line; *p; ++p) {
        unsigned char ch = *p;
        if(ch < 32 || ch == 127) return false;
        if(!escaped && ch == '\\') {
            escaped = true;
            continue;
        }
        if(!escaped && ch == ',') {
            if(field == 2) return false;
            fields[field++][length] = '\0';
            length = 0;
            continue;
        }
        if(length >= LM_FIELD_SIZE - 1) return false;
        fields[field][length++] = (char)ch;
        escaped = false;
    }
    fields[field][length] = '\0';
    return !escaped && field == 2 && login->name[0] && login->password[0];
}

static void lm_add_line(LoginManager* app, char* line, size_t length, bool overflow, char* storage) {
    if(length && line[length - 1] == '\r') --length;
    line[length] = '\0';
    if(!length && !overflow) return;

    Login login;
    if(!overflow && app->count < LM_MAX_LOGINS && lm_parse(line, &login)) {
        lm_clear(storage, length);
        lm_pack_login(&login, &app->logins[app->count++], storage, false);
    } else {
        ++app->invalid;
    }
    lm_clear(&login, sizeof(login));
}

static uint32_t lm_read_le32(const uint8_t* bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static bool lm_header_valid(const uint8_t* header, uint64_t file_size) {
    uint32_t rounds = lm_read_le32(header + 4);
    uint32_t length = lm_read_le32(header + 36);
    bool v2 = memcmp(header, "LMV2", 4) == 0;
    return (v2 || memcmp(header, "LMV1", 4) == 0) && rounds >= 10000 && rounds <= LM_KDF_MAX_ITERATIONS &&
           length > (v2 ? 2u : 0u) && length <= LM_MAX_PAYLOAD + (v2 ? 2u : 0u) &&
           file_size == (uint64_t)LM_HEADER_SIZE + length + 16;
}

typedef struct {
    uint32_t percent;
} KeyProgress;

static void lm_key_progress(Canvas* canvas, void* context) {
    KeyProgress* progress = context;
    unsigned percent = __atomic_load_n(&progress->percent, __ATOMIC_RELAXED);
    char line[24];
    snprintf(line, sizeof(line), "Unlock key: %u%%", percent);
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 5, 18, "Lockfin");
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 5, 36, line);
    canvas_draw_frame(canvas, 5, 44, 102, 8);
    if(percent) canvas_draw_box(canvas, 6, 45, percent, 6);
}

/* PBKDF2-HMAC-SHA256, one 32-byte output block, using mbedTLS HMAC. */
static bool lm_derive_key(
    const char* master,
    const uint8_t* salt,
    uint32_t rounds,
    uint8_t* key) {
    Gui* gui = furi_record_open(RECORD_GUI);
    KeyProgress progress = {0};
    ViewPort* view = view_port_alloc();
    view_port_draw_callback_set(view, lm_key_progress, &progress);
    gui_add_view_port(gui, view, GuiLayerFullscreen);
    view_port_update(view);
    mbedtls_md_context_t context;
    mbedtls_md_init(&context);
    uint8_t block[20] = {0};
    uint8_t u[32] = {0};
    memcpy(block, salt, 16);
    block[19] = 1;
    memset(key, 0, 32);
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    bool ok = info && mbedtls_md_setup(&context, info, 1) == 0;
    if(ok) {
        ok = mbedtls_md_hmac_starts(&context, (const uint8_t*)master, strlen(master)) == 0 &&
             mbedtls_md_hmac_update(&context, block, sizeof(block)) == 0 &&
             mbedtls_md_hmac_finish(&context, u) == 0;
    }
    if(ok) memcpy(key, u, 32);
    for(uint32_t i = 1; ok && i < rounds; ++i) {
        if((i % 1024) == 0) {
            __atomic_store_n(&progress.percent, (100U * i) / rounds, __ATOMIC_RELAXED);
            view_port_update(view);
            furi_delay_tick(1);
        }
        ok = mbedtls_md_hmac_reset(&context) == 0 &&
             mbedtls_md_hmac_update(&context, u, sizeof(u)) == 0 &&
             mbedtls_md_hmac_finish(&context, u) == 0;
        if(ok) {
            for(size_t j = 0; j < 32; ++j) key[j] ^= u[j];
        }
    }
    /* La ultima iteracion no coincide necesariamente con el refresco de 1024. */
    if(ok) {
        __atomic_store_n(&progress.percent, 100U, __ATOMIC_RELAXED);
        view_port_update(view);
        furi_delay_ms(50);
    }
    mbedtls_md_free(&context);
    gui_remove_view_port(gui, view);
    view_port_free(view);
    furi_record_close(RECORD_GUI);
    lm_clear(block, sizeof(block));
    lm_clear(u, sizeof(u));
    if(!ok) lm_clear(key, 32);
    return ok;
}

/* Independent Python AESGCM/PBKDF2 vector, including an LMV1-sized AAD and
 * a partial final block. Never operates on the user's file or credentials. */
static bool lm_crypto_compatible(void) {
    static const uint8_t header[] = {0x4c, 0x4d, 0x56, 0x31, 0x10, 0x27, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x01, 0x00, 0x00, 0x00};
    static const uint8_t expected_key[] = {0xa7, 0x76, 0x89, 0x92, 0xfa, 0x6d, 0xfa, 0xa7, 0x61, 0x5a, 0x9e, 0xc6, 0x85, 0xd0, 0x3d, 0xcd, 0x3b, 0x59, 0xbd, 0x55, 0x5e, 0xd3, 0xdb, 0x58, 0xc1, 0x91, 0x54, 0xfd, 0xd2, 0x40, 0xb8, 0xd0};
    static const uint8_t sealed[] = {0xb6, 0x34, 0x0a, 0x17, 0xd5, 0x66, 0xa3, 0x0d, 0xfb, 0x52, 0x0c, 0xd2, 0x24, 0x23, 0xbd, 0x18, 0xfc};
    _Alignas(4) uint8_t key[32] = {0};
    uint8_t plain = 0;
    bool ok = lm_derive_key("Lockfin-test", header + 8, 32, key) &&
              memcmp(key, expected_key, sizeof(key)) == 0 &&
              furi_hal_crypto_gcm_decrypt_and_verify(
                  key, header + 24, header, sizeof(header), sealed, &plain, 1, sealed + 1)
                  == FuriHalCryptoGCMStateOk && plain == '\n';
    lm_clear(key, sizeof(key));
    return ok;
}

/* Adopt legacy files without overwriting an existing destination. */
static bool lm_adopt_legacy_file(Storage* storage, const char* old_path, const char* path) {
    FS_Error error = storage_common_stat(storage, path, NULL);
    if(error == FSE_OK) return true;
    if(error != FSE_NOT_EXIST) return false;
    error = storage_common_stat(storage, old_path, NULL);
    if(error == FSE_NOT_EXIST) return true;
    if(error != FSE_OK) return false;
    /* The SDK copy operation opens the destination with FSOM_CREATE_NEW. */
    error = storage_common_copy(storage, old_path, path);
    if(error == FSE_OK) return storage_simply_remove(storage, old_path);
    return error == FSE_EXIST;
}

static VaultState lm_probe(void) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(!storage_simply_mkdir(storage, EXT_PATH("apps_data")) ||
       !storage_simply_mkdir(storage, EXT_PATH("apps_data/lockfin"))) {
        furi_record_close(RECORD_STORAGE);
        return VaultCryptoError;
    }
    if(!lm_adopt_legacy_file(storage, LM_BACKUP_PATH, LM_VAULT_PATH) ||
       !lm_adopt_legacy_file(storage, EXT_PATH("apps_data/login_manager/vault.lmv"), LM_VAULT_PATH) ||
       !lm_adopt_legacy_file(storage, EXT_PATH("apps_data/login_manager/vault.lmv.bak"), LM_VAULT_PATH) ||
       !lm_adopt_legacy_file(storage, EXT_PATH("apps_data/login_manager/.bt.keys"),
                             EXT_PATH("apps_data/lockfin/.bt.keys"))) {
        furi_record_close(RECORD_STORAGE);
        return VaultCryptoError;
    }
    File* file = storage_file_alloc(storage);
    VaultState state = VaultCryptoError;
    if(storage_file_open(file, LM_VAULT_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        uint8_t header[LM_HEADER_SIZE];
        state = VaultBadFormat;
        if(storage_file_read(file, header, sizeof(header)) == sizeof(header) &&
           lm_header_valid(header, storage_file_size(file))) {
            state = VaultLocked;
        }
        storage_file_close(file);
    } else if(storage_file_get_error(file) == FSE_NOT_EXIST) {
        state = VaultMissing;
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return state;
}

static VaultState lm_load(LoginManager* app, const char* master, const uint8_t* cached_key, const uint8_t* bound_salt) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    uint8_t header[LM_HEADER_SIZE] = {0};
    uint8_t key[32] = {0};
    uint8_t* ciphertext = NULL;
    uint32_t size = 0;
    bool opened = storage_file_open(file, LM_VAULT_PATH, FSAM_READ, FSOM_OPEN_EXISTING);
    VaultState state = opened ? VaultBadFormat : VaultMissing;
    if(!opened) goto cleanup;
    if(storage_file_read(file, header, sizeof(header)) != sizeof(header) ||
       !lm_header_valid(header, storage_file_size(file))) {
        goto cleanup;
    }
    size = lm_read_le32(header + 36);
    if(memmgr_get_free_heap() < (size_t)size + 16 + 8192) {
        state = VaultCryptoError;
        goto cleanup;
    }
    ciphertext = malloc(size + 16);
    if(!ciphertext) {
        state = VaultCryptoError;
        goto cleanup;
    }
    if(storage_file_read(file, ciphertext, size + 16) != size + 16) goto cleanup;
    if(cached_key) {
        if(!bound_salt || memcmp(bound_salt, header + 8, 16) != 0) goto cleanup;
        memcpy(key, cached_key, sizeof(key));
    } else if(!master || !lm_derive_key(master, header + 8, lm_read_le32(header + 4), key)) {
        state = VaultCryptoError;
        goto cleanup;
    }
    FuriHalCryptoGCMState result = furi_hal_crypto_gcm_decrypt_and_verify(
        key,
        header + 24,
        header,
        sizeof(header),
        ciphertext,
        ciphertext,
        size,
        ciphertext + size);
    if(result != FuriHalCryptoGCMStateOk) {
        state = result == FuriHalCryptoGCMStateAuthFailure ?
                    (lm_crypto_compatible() ? VaultBadPassword : VaultInteropError) : VaultCryptoError;
        goto cleanup;
    }
    const uint8_t* plaintext = ciphertext;
    size_t start = header[3] == '2' ? 2 : 0;
    size_t favorites = start ? plaintext[0] | ((size_t)plaintext[1] << 8) : 0;
    if(memchr(plaintext + start, 0, size - start)) goto cleanup;
    size_t entries = 0;
    for(size_t i = start; i < size; ++i) {
        if((i == start || plaintext[i-1] == '\n') && plaintext[i] != '\n') ++entries;
    }
    if(entries > LM_MAX_LOGINS) goto cleanup;
    if(!lm_reserve(app, entries)) {
        state = VaultCryptoError;
        goto cleanup;
    }
    {
        /* Decode each line into its original space. Even the final line without
           a newline has space for its terminator in the consumed tag. */
        memcpy(app->saved_tag, ciphertext + size, 16);
        size_t line_start = start;
        char line[LM_LINE_SIZE] = {0};
        size_t length = 0;
        bool overflow = false;
        for(size_t i = start; i < size; ++i) {
            uint8_t ch = plaintext[i];
            if(ch == '\n') {
                lm_add_line(app, line, length, overflow, (char*)ciphertext + line_start);
                line_start = i + 1;
                length = 0;
                overflow = false;
            } else if(length < sizeof(line) - 1) {
                line[length++] = (char)ch;
            } else {
                overflow = true;
            }
        }
        if(length || overflow) lm_add_line(app, line, length, overflow, (char*)ciphertext + line_start);
        lm_clear(line, sizeof(line));
    }
    app->loaded_data = ciphertext;
    app->loaded_size = size + 16;
    ciphertext = NULL;
    state = !app->invalid && favorites <= app->count ? VaultReady : VaultBadFormat;
    if(state == VaultReady) {
        app->favorites = favorites;
        memcpy(app->session_key, key, 32);
        memcpy(app->salt, header + 8, 16);
        app->rounds = lm_read_le32(header + 4);
        app->session_key_ready = true;
        app->has_saved = true;
    }
cleanup:
    lm_clear(key, sizeof(key));
    if(ciphertext) {
        lm_clear(ciphertext, size + 16);
        free(ciphertext);
    }
    if(state != VaultReady) {
        lm_release_logins(app);
        app->count = 0;
        app->invalid = 0;
    }
    if(opened) storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return state;
}

typedef struct {
    ViewDispatcher* dispatcher;
    bool accepted;
    uint32_t selected;
} UnlockPrompt;

static void lm_unlock_submit(void* context) {
    UnlockPrompt* prompt = context;
    prompt->accepted = true;
    view_dispatcher_stop(prompt->dispatcher);
}

static bool lm_unlock_back(void* context) {
    UnlockPrompt* prompt = context;
    view_dispatcher_stop(prompt->dispatcher);
    return true;
}

static bool lm_master_valid(const char* text, FuriString* error, void* context) {
    UNUSED(context);
    size_t length = strlen(text);
    if(length < 8 || length >= LM_MASTER_SIZE) {
        furi_string_set(error, "Use 8 to 63 characters");
        return false;
    }
    for(const unsigned char* p = (const unsigned char*)text; *p; ++p) {
        if(*p < 32 || *p > 126) {
            furi_string_set(error, "Use printable ASCII");
            return false;
        }
    }
    return true;
}

static bool lm_text(
    Gui* gui, const char* title, char* buffer, size_t size, size_t minimum, bool master) {
    UnlockPrompt prompt = {.dispatcher = view_dispatcher_alloc(), .accepted = false};
    TextInput* input = text_input_alloc();
    text_input_set_header_text(input, title);
    text_input_set_minimum_length(input, minimum);
    if(master) text_input_set_validator(input, lm_master_valid, NULL);
    text_input_set_result_callback(
        input, lm_unlock_submit, &prompt, buffer, size, false);
    view_dispatcher_set_event_callback_context(prompt.dispatcher, &prompt);
    view_dispatcher_set_navigation_event_callback(prompt.dispatcher, lm_unlock_back);
    view_dispatcher_add_view(prompt.dispatcher, 0, text_input_get_view(input));
    view_dispatcher_attach_to_gui(prompt.dispatcher, gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_switch_to_view(prompt.dispatcher, 0);
    view_dispatcher_run(prompt.dispatcher);
    view_dispatcher_remove_view(prompt.dispatcher, 0);
    text_input_free(input);
    view_dispatcher_free(prompt.dispatcher);
    return prompt.accepted;
}

static bool lm_prompt(Gui* gui, char* master) {
    return lm_text(gui, "Vault password", master, LM_MASTER_SIZE, 8, true);
}

static void lm_choice_selected(void* context, uint32_t index) {
    UnlockPrompt* prompt = context;
    prompt->selected = index;
    prompt->accepted = true;
    view_dispatcher_stop(prompt->dispatcher);
}

static int lm_choice(
    Gui* gui, const char* title, const char* const* labels, size_t count, uint32_t initial) {
    UnlockPrompt prompt = {.dispatcher = view_dispatcher_alloc(), .accepted = false};
    Submenu* menu = submenu_alloc();
    submenu_set_header(menu, title);
    for(size_t i = 0; i < count; ++i) {
        submenu_add_item(menu, labels[i], i, lm_choice_selected, &prompt);
    }
    submenu_set_selected_item(menu, initial);
    view_dispatcher_set_event_callback_context(prompt.dispatcher, &prompt);
    view_dispatcher_set_navigation_event_callback(prompt.dispatcher, lm_unlock_back);
    view_dispatcher_add_view(prompt.dispatcher, 0, submenu_get_view(menu));
    view_dispatcher_attach_to_gui(prompt.dispatcher, gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_switch_to_view(prompt.dispatcher, 0);
    view_dispatcher_run(prompt.dispatcher);
    view_dispatcher_remove_view(prompt.dispatcher, 0);
    submenu_free(menu);
    view_dispatcher_free(prompt.dispatcher);
    return prompt.accepted ? (int)prompt.selected : -1;
}

static void lm_notice(Gui* gui, const char* title) {
    const char* const items[] = {"Back"};
    lm_choice(gui, title, items, 1, 0);
}

static void lm_put_le32(uint8_t* output, uint32_t value) {
    for(size_t i = 0; i < 4; ++i) output[i] = (uint8_t)(value >> (i * 8));
}

static bool lm_disk_matches(Storage* storage, LoginManager* app) {
    if(!app->has_saved) return !storage_file_exists(storage, LM_VAULT_PATH);
    File* file = storage_file_alloc(storage);
    uint8_t tag[16];
    bool opened = storage_file_open(file, LM_VAULT_PATH, FSAM_READ, FSOM_OPEN_EXISTING);
    bool same = false;
    if(opened) {
        uint64_t size = storage_file_size(file);
        if(size >= LM_HEADER_SIZE + 17 && size <= LM_HEADER_SIZE + LM_MAX_PAYLOAD + 18 &&
           storage_file_seek(file, (uint32_t)size - 16, true) &&
           storage_file_read(file, tag, sizeof(tag)) == sizeof(tag)) {
            same = memcmp(tag, app->saved_tag, 16) == 0;
        }
        storage_file_close(file);
    }
    storage_file_free(file);
    return same;
}

/* Encrypted temporary + backup; never remove the previous vault before a full sync. */
static bool lm_save(LoginManager* app) {
    if(!app->session_key_ready || app->count > LM_MAX_LOGINS) return false;
    size_t length = app->count ? 0 : 1;
    for(size_t i = 0; i < app->count; ++i) {
        const char* fields[] = {app->logins[i].name, app->logins[i].username,
                                app->logins[i].password};
        for(size_t j = 0; j < 3; ++j) {
            for(const char* q = fields[j]; *q; ++q) length += (*q == ',' || *q == '\\') ? 2 : 1;
            ++length;
        }
    }
    if(length > LM_MAX_PAYLOAD || app->favorites > app->count) return false;
    if(app->favorites) length += 2;
    if(memmgr_get_free_heap() < LM_HEADER_SIZE + length + 16 + 8192) return false;
    uint8_t* blob = malloc(LM_HEADER_SIZE + length + 16);
    if(!blob) return false;
    uint8_t* plaintext = blob + LM_HEADER_SIZE;
    size_t position = 0;
    if(app->favorites) {
        plaintext[position++] = (uint8_t)app->favorites;
        plaintext[position++] = (uint8_t)(app->favorites >> 8);
    }
    if(!app->count) plaintext[position++] = '\n';
    for(size_t i = 0; i < app->count; ++i) {
        const char* fields[] = {app->logins[i].name, app->logins[i].username,
                                app->logins[i].password};
        for(size_t j = 0; j < 3; ++j) {
            for(const char* q = fields[j]; *q; ++q) {
                if(*q == ',' || *q == '\\') plaintext[position++] = '\\';
                plaintext[position++] = (uint8_t)*q;
            }
            plaintext[position++] = j == 2 ? '\n' : ',';
        }
    }
    furi_check(position == length);
    memcpy(blob, app->favorites ? "LMV2" : "LMV1", 4);
    lm_put_le32(blob + 4, app->rounds);
    memcpy(blob + 8, app->salt, 16);
    furi_hal_random_fill_buf(blob + 24, 12);
    lm_put_le32(blob + 36, length);
    bool ok = furi_hal_crypto_gcm_encrypt_and_tag(
        app->session_key, blob + 24, blob, LM_HEADER_SIZE, plaintext,
        blob + LM_HEADER_SIZE, length, blob + LM_HEADER_SIZE + length) == FuriHalCryptoGCMStateOk;
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    bool moved_old = false;
    if(!ok || !storage_simply_mkdir(storage, EXT_PATH("apps_data")) ||
       !storage_simply_mkdir(storage, EXT_PATH("apps_data/lockfin")) ||
       !lm_disk_matches(storage, app) || !storage_simply_remove(storage, LM_TEMP_PATH)) {
        ok = false; goto cleanup;
    }
    ok = storage_file_open(file, LM_TEMP_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS);
    if(ok) {
        ok = storage_file_write(file, blob, LM_HEADER_SIZE + length + 16) ==
             LM_HEADER_SIZE + length + 16 && storage_file_sync(file);
        storage_file_close(file);
    }
    if(!ok) goto cleanup;
    if(app->has_saved) {
        if(!storage_simply_remove(storage, LM_BACKUP_PATH) ||
           storage_common_rename(storage, LM_VAULT_PATH, LM_BACKUP_PATH) != FSE_OK) {
            ok = false; goto cleanup;
        }
        moved_old = true;
    }
    if(storage_common_rename(storage, LM_TEMP_PATH, LM_VAULT_PATH) != FSE_OK) {
        if(moved_old) storage_common_rename(storage, LM_BACKUP_PATH, LM_VAULT_PATH);
        ok = false; goto cleanup;
    }
    memcpy(app->saved_tag, blob + LM_HEADER_SIZE + length, 16);
    app->has_saved = true;
    if(moved_old) storage_simply_remove(storage, LM_BACKUP_PATH);
cleanup:
    if(!ok) storage_simply_remove(storage, LM_TEMP_PATH);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    lm_clear(blob, LM_HEADER_SIZE + length + 16);
    free(blob);
    return ok;
}

static uint8_t lm_random_below(uint8_t bound) {
    uint8_t value;
    uint16_t limit = 256 - (256 % bound);
    do { furi_hal_random_fill_buf(&value, 1); } while(value >= limit);
    return value % bound;
}

enum {
    GenLength, GenUpper, GenLower, GenDigits, GenSymbols,
    GenMinDigits, GenMinSymbols, GenAvoidSimilar, GenOptionCount
};

typedef struct {
    const char* label;
    uint8_t min;
    uint8_t max;
} GeneratorOption;

static const GeneratorOption generator_options[GenOptionCount] = {
    [GenLength] = {"Length", 5, LM_FIELD_SIZE - 1},
    [GenUpper] = {"Uppercase A-Z", 0, 1},
    [GenLower] = {"Lowercase a-z", 0, 1},
    [GenDigits] = {"Digits 0-9", 0, 1},
    [GenSymbols] = {"Symbols", 0, 1},
    [GenMinDigits] = {"Min. digits", 0, LM_FIELD_SIZE - 1},
    [GenMinSymbols] = {"Min. symbols", 0, LM_FIELD_SIZE - 1},
    [GenAvoidSimilar] = {"Avoid lookalikes", 0, 1},
};

static const char* lm_generate(char* password, const uint8_t options[GenOptionCount]) {
    const char* const groups[] = {
        options[GenAvoidSimilar] ? "ABCDEFGHJKLMNPQRSTUVWXYZ" : "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        options[GenAvoidSimilar] ? "abcdefghijkmnopqrstuvwxyz" : "abcdefghijklmnopqrstuvwxyz",
        options[GenAvoidSimilar] ? "23456789" : "0123456789",
        "!@#$%*-_+=",
    };
    size_t length = options[GenLength];
    if(length < generator_options[GenLength].min || length >= LM_FIELD_SIZE) return "Check length";
    char alphabet[80];
    size_t alphabet_length = 0;
    uint8_t required[] = {1, 1, options[GenMinDigits], options[GenMinSymbols]};
    size_t minimum = 0;
    for(size_t i = 0; i < COUNT_OF(groups); ++i) {
        if(!options[GenUpper + i]) continue;
        size_t n = strlen(groups[i]);
        memcpy(alphabet + alphabet_length, groups[i], n);
        alphabet_length += n;
        minimum += required[i];
    }
    if(!alphabet_length) return "Enable a character set";
    if(minimum > length) return "Minimums exceed length";
    size_t used = 0;
    for(size_t i = 0; i < COUNT_OF(groups); ++i) {
        if(!options[GenUpper + i]) continue;
        for(size_t j = 0; j < required[i]; ++j)
            password[used++] = groups[i][lm_random_below(strlen(groups[i]))];
    }
    while(used < length) password[used++] = alphabet[lm_random_below(alphabet_length)];
    for(size_t i = length - 1; i > 0; --i) {
        size_t j = lm_random_below(i + 1);
        char temp = password[i];
        password[i] = password[j];
        password[j] = temp;
    }
    password[length] = 0;
    return NULL;
}

static void lm_generator_value(VariableItem* item) {
    const GeneratorOption* option = variable_item_get_context(item);
    uint8_t value = option->min + variable_item_get_current_value_index(item);
    char text[4];
    snprintf(text, sizeof(text), "%u", (unsigned)value);
    variable_item_set_current_value_text(item, option->max == 1 ? (value ? "On" : "Off") : text);
}

static void lm_generator_submit(void* context, uint32_t index) {
    if(index == 0) lm_unlock_submit(context);
}

static bool lm_generator_settings(Gui* gui, uint8_t options[GenOptionCount]) {
    UnlockPrompt prompt = {.dispatcher = view_dispatcher_alloc()};
    VariableItemList* list = variable_item_list_alloc();
    variable_item_list_add(list, "Generate password", 1, NULL, NULL);
    VariableItem* items[GenOptionCount];
    for(size_t i = 0; i < GenOptionCount; ++i) {
        const GeneratorOption* opt = &generator_options[i];
        items[i] = variable_item_list_add(list, opt->label, opt->max - opt->min + 1,
                                          lm_generator_value, (void*)opt);
        variable_item_set_current_value_index(items[i], options[i] - opt->min);
        lm_generator_value(items[i]);
    }
    variable_item_list_set_enter_callback(list, lm_generator_submit, &prompt);
    view_dispatcher_set_event_callback_context(prompt.dispatcher, &prompt);
    view_dispatcher_set_navigation_event_callback(prompt.dispatcher, lm_unlock_back);
    view_dispatcher_add_view(prompt.dispatcher, 0, variable_item_list_get_view(list));
    view_dispatcher_attach_to_gui(prompt.dispatcher, gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_switch_to_view(prompt.dispatcher, 0);
    view_dispatcher_run(prompt.dispatcher);
    view_dispatcher_remove_view(prompt.dispatcher, 0);
    for(size_t i = 0; i < GenOptionCount; ++i) {
        options[i] = generator_options[i].min + variable_item_get_current_value_index(items[i]);
    }
    variable_item_list_free(list);
    view_dispatcher_free(prompt.dispatcher);
    return prompt.accepted;
}

static bool lm_generate_account_password(Gui* gui, char* password) {
    uint8_t options[GenOptionCount] = {20, 1, 1, 1, 1, 1, 1, 1};
    const char* const actions[] = {"Use password", "Generate again", "View / edit", "Options"};
    while(lm_generator_settings(gui, options)) {
        for(;;) {
            const char* error = lm_generate(password, options);
            if(error) {
                lm_notice(gui, error);
                break;
            }
            int action = lm_choice(gui, "Password ready", actions, COUNT_OF(actions), 0);
            if(action == 0) return true;
            if(action == 2) return lm_text(gui, "Account password", password, LM_FIELD_SIZE, 1, false);
            if(action != 1) break;
        }
    }
    return false;
}

static void lm_bt_status(BtStatus status, void* context) {
    LoginManager* app = context;
    __atomic_store_n(&app->bt_connected, status == BtStatusConnected, __ATOMIC_RELEASE);
}

static void lm_stop_ble(LoginManager* app) {
    if(app->bt) {
        bt_set_status_changed_callback(app->bt, NULL, NULL);
        if(app->bt_profile) ble_profile_hid_kb_release_all(app->bt_profile);
        bt_disconnect(app->bt);
        furi_delay_ms(200); /* Allow the radio core to finish writing bond data. */
        bt_keys_storage_set_default_path(app->bt);
        bt_profile_restore_default(app->bt);
        furi_record_close(RECORD_BT);
        app->bt = NULL;
        app->bt_profile = NULL;
        __atomic_store_n(&app->bt_connected, false, __ATOMIC_RELEASE);
    }
}

static void lm_stop_keyboard(LoginManager* app) {
    lm_stop_ble(app);
    if(app->owns_usb) {
        furi_hal_hid_kb_release_all();
        furi_hal_usb_set_config(app->previous_usb, NULL);
        app->owns_usb = false;
    }
}

static void lm_lock(LoginManager* app) {
    lm_stop_keyboard(app);
    VaultState state = lm_probe();
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    lm_release_logins(app);
    lm_clear(app->session_key, sizeof(app->session_key));
    lm_clear(app->salt, sizeof(app->salt));
    lm_clear(app->saved_tag, sizeof(app->saved_tag));
    app->session_key_ready = app->has_saved = false;
    app->count = app->invalid = app->selected = app->scroll = 0;
    app->details = false;
    app->shortcuts = false;
    app->vault_state = state;
    app->status = StatusReady;
    furi_mutex_release(app->mutex);
}

static bool lm_new_master(Gui* gui, char* master) {
    char confirmation[LM_MASTER_SIZE] = {0};
    bool ok = lm_text(gui, "New vault password", master, LM_MASTER_SIZE, 8, true) &&
              lm_text(gui, "Confirm password", confirmation, sizeof(confirmation), 8, true);
    if(ok && strcmp(master, confirmation) != 0) {
        lm_notice(gui, "Passwords differ"); ok = false;
    }
    lm_clear(confirmation, sizeof(confirmation));
    return ok;
}

static bool lm_change_master(LoginManager* app, Gui* gui, bool create) {
    char master[LM_MASTER_SIZE] = {0};
    uint8_t salt[16], key[32], old_salt[16], old_key[32];
    uint32_t old_rounds = app->rounds;
    memcpy(old_salt, app->salt, 16); memcpy(old_key, app->session_key, 32);
    bool ok = lm_new_master(gui, master);
    if(ok) {
        furi_hal_random_fill_buf(salt, sizeof(salt));
        ok = lm_derive_key(master, salt, LM_KDF_ITERATIONS, key);
    }
    lm_clear(master, sizeof(master));
    if(ok) {
        memcpy(app->salt, salt, 16); memcpy(app->session_key, key, 32);
        app->rounds = LM_KDF_ITERATIONS; app->session_key_ready = true;
        ok = lm_save(app);
        if(ok) {
            app->vault_state = VaultReady;
            app->status = StatusSaved;
        } else {
            memcpy(app->salt, old_salt, 16); memcpy(app->session_key, old_key, 32);
            app->rounds = old_rounds;
            if(create) lm_lock(app);
            lm_notice(gui, "Save failed");
        }
    }
    lm_clear(salt, sizeof(salt)); lm_clear(key, sizeof(key));
    lm_clear(old_salt, sizeof(old_salt)); lm_clear(old_key, sizeof(old_key));
    return ok;
}

static void lm_edit_login(LoginManager* app, Gui* gui, bool add) {
    if(add && app->count >= LM_MAX_LOGINS) { lm_notice(gui, "Vault is full"); return; }
    Login draft = {0};
    if(!add) {
        StoredLogin entry = app->logins[app->selected];
        strcpy(draft.name, entry.name);
        strcpy(draft.username, entry.username);
        strcpy(draft.password, entry.password);
    }
    bool accepted = lm_text(gui, "Account name", draft.name, sizeof(draft.name), 1, false) &&
                    lm_text(gui, "Username (optional)", draft.username, sizeof(draft.username), 0, false);
    if(accepted) {
        const char* const choices[] = {"Enter password", "Generate password", "Keep current"};
        int choice = lm_choice(gui, "Password", choices, add ? 2 : 3, add ? 0 : 2);
        if(choice == 0) {
            accepted = lm_text(gui, "Account password", draft.password, sizeof(draft.password), 1, false);
        } else if(choice == 1) {
            accepted = lm_generate_account_password(gui, draft.password);
        } else if(choice != 2) {
            accepted = false;
        }
    }
    if(accepted) {
        StoredLogin old = {0}, replacement = {0};
        size_t index = add ? app->count : app->selected;
        if(!add) old = app->logins[index];
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        if((add && !lm_reserve(app, index + 1)) || !lm_store_login(&draft, &replacement)) {
            furi_mutex_release(app->mutex);
            lm_clear(&draft, sizeof(draft));
            lm_notice(gui, "Not enough memory");
            return;
        }
        app->logins[index] = replacement;
        if(add) ++app->count;
        furi_mutex_release(app->mutex);
        bool saved = lm_save(app);
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        if(!saved) {
            app->logins[index] = old;
            if(add) --app->count;
            app->status = StatusSaveFailed;
        } else {
            app->selected = index;
            app->details = true;
            app->action = ActionUsername;
            app->status = StatusSaved;
        }
        furi_mutex_release(app->mutex);
        lm_free_login(saved ? old : replacement);
        if(!saved) lm_notice(gui, "Save failed");
    }
    lm_clear(&draft, sizeof(draft));
}

static void lm_delete_login(LoginManager* app, Gui* gui) {
    const char* const choices[] = {"Cancel", "Delete login"};
    if(lm_choice(gui, "Delete this login?", choices, 2, 0) != 1) return;
    size_t index = app->selected;
    StoredLogin old = app->logins[index];
    bool favorite = index < app->favorites;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    memmove(app->logins + index, app->logins + index + 1,
            (app->count - index - 1) * sizeof(StoredLogin));
    --app->count;
    if(favorite) --app->favorites;
    lm_clear(&app->logins[app->count], sizeof(StoredLogin));
    furi_mutex_release(app->mutex);
    bool saved = lm_save(app);
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    if(!saved) {
        memmove(app->logins + index + 1, app->logins + index,
                (app->count - index) * sizeof(StoredLogin));
        app->logins[index] = old; ++app->count;
        if(favorite) ++app->favorites;
        app->status = StatusSaveFailed;
    } else {
        app->selected = app->count ? (index < app->count ? index : app->count - 1) : 0;
        app->scroll = 0; app->details = false; app->status = StatusSaved;
    }
    furi_mutex_release(app->mutex);
    if(saved) lm_free_login(old);
    if(!saved) lm_notice(gui, "Save failed");
}

/* Only the wrapped unlock key is cached, in internal storage. The vault
 * remains a normal portable LMV1 file. Three durable attempts per enrollment. */
#define LM_PIN_PATH INT_PATH(".lockfin-pin1")
#define LM_PIN_LIMIT 3
typedef struct {
    uint8_t magic[4], salt[16], challenge[16], nonce[12], ciphertext[32], tag[16], failures;
} PinRecord;
_Static_assert(sizeof(PinRecord) == 97, "PIN record layout");

static bool lm_pin_io(PinRecord* record, bool save) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    bool opened = storage_file_open(file, LM_PIN_PATH, save ? FSAM_WRITE : FSAM_READ,
                                    save ? FSOM_CREATE_ALWAYS : FSOM_OPEN_EXISTING);
    bool ok = false;
    if(opened) {
        if(save) {
            ok = storage_file_write(file, record, sizeof(*record)) == sizeof(*record) &&
                 storage_file_sync(file);
        } else {
            ok = storage_file_size(file) == sizeof(*record) &&
                 storage_file_read(file, record, sizeof(*record)) == sizeof(*record) &&
                 memcmp(record->magic, "LFP1", 4) == 0;
        }
        storage_file_close(file);
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

static bool lm_pin_counter(uint8_t count) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    bool ok = storage_file_open(file, LM_PIN_PATH, FSAM_READ_WRITE, FSOM_OPEN_EXISTING);
    if(ok) {
        ok = storage_file_seek(file, offsetof(PinRecord, failures), true) &&
             storage_file_write(file, &count, 1) == 1 && storage_file_sync(file);
        storage_file_close(file);
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

static bool lm_pin_wrap_key(const PinRecord* record, const char* pin, uint8_t* out) {
    const uint8_t slot = FURI_HAL_CRYPTO_ENCLAVE_UNIQUE_KEY_SLOT;
    _Alignas(4) uint8_t iv[16] = {0}, challenge[16], device_secret[16];
    memcpy(challenge, record->challenge, 16);
    if(!furi_hal_bt_is_alive() || !furi_hal_crypto_enclave_ensure_key(slot) ||
       !furi_hal_crypto_enclave_load_key(slot, iv)) return false;
    bool ok = furi_hal_crypto_encrypt(challenge, device_secret, 16);
    bool unloaded = furi_hal_crypto_enclave_unload_key(slot);
    const mbedtls_md_info_t* sha = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    ok = ok && unloaded && sha &&
         mbedtls_md_hmac(sha, device_secret, 16, (const uint8_t*)pin, 6, out) == 0;
    lm_clear(device_secret, sizeof(device_secret));
    return ok;
}

static bool lm_pin_entry(Gui* gui, const char* label, char pin[7]) {
    if(!lm_text(gui, label, pin, 7, 6, false)) return false;
    if(strlen(pin) == 6 && strspn(pin, "0123456789") == 6) return true;
    lm_notice(gui, "Use six digits");
    return false;
}

static void lm_pin_setup(LoginManager* app, Gui* gui) {
    PinRecord record = {0};
    char pin[7] = {0}, confirm[7] = {0};
    _Alignas(4) uint8_t key[32] = {0};
    if(!app->session_key_ready || !lm_pin_entry(gui, "New 6-digit PIN", pin) ||
       !lm_pin_entry(gui, "Confirm PIN", confirm)) goto done;
    if(memcmp(pin, confirm, 6) != 0) {
        lm_notice(gui, "PINs differ");
        goto done;
    }
    memcpy(record.magic, "LFP1", 4);
    memcpy(record.salt, app->salt, 16);
    furi_hal_random_fill_buf(record.challenge, 16);
    furi_hal_random_fill_buf(record.nonce, 12);
    bool ok = lm_pin_wrap_key(&record, pin, key) &&
              furi_hal_crypto_gcm_encrypt_and_tag(key, record.nonce, (const uint8_t*)&record,
                  offsetof(PinRecord, ciphertext), app->session_key, record.ciphertext,
                  32, record.tag) == FuriHalCryptoGCMStateOk && lm_pin_io(&record, true);
    lm_notice(gui, ok ? "Quick PIN enabled" : "Could not set PIN");
done:
    lm_clear(pin, sizeof(pin));
    lm_clear(confirm, sizeof(confirm));
    lm_clear(key, sizeof(key));
    lm_clear(&record, sizeof(record));
}

/* El PIN recupera la clave envuelta; no vuelve a ejecutar PBKDF2. */
static void lm_pin_progress(Canvas* canvas, void* context) {
    UNUSED(context);
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 5, 20, "Unlocking vault");
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 5, 39, "Checking Quick PIN...");
    canvas_draw_str(canvas, 5, 55, "Please wait");
}

static bool lm_quick_unlock(LoginManager* app, Gui* gui, bool* available) {
    *available = false;
    PinRecord record = {0};
    if(!lm_pin_io(&record, false) || record.failures >= LM_PIN_LIMIT) return false;
    /* A different vault or PC re-encryption needs its own master password. */
    uint8_t header[LM_HEADER_SIZE];
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    bool opened = storage_file_open(file, LM_VAULT_PATH, FSAM_READ, FSOM_OPEN_EXISTING);
    bool bound = opened && storage_file_read(file, header, sizeof(header)) == sizeof(header) &&
                 memcmp(record.salt, header + 8, 16) == 0;
    if(opened) storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    if(!bound) return false;
    *available = true;
    while(record.failures < LM_PIN_LIMIT) {
        char pin[7] = {0};
        _Alignas(4) uint8_t wrapping[32] = {0}, key[32] = {0};
        bool entered = lm_pin_entry(gui, "Quick PIN (Back: master)", pin);
        ViewPort* busy = NULL;
        if(entered) {
            busy = view_port_alloc();
            view_port_draw_callback_set(busy, lm_pin_progress, NULL);
            gui_add_view_port(gui, busy, GuiLayerFullscreen);
            view_port_update(busy);
        }
        bool prepared = entered && lm_pin_wrap_key(&record, pin, wrapping) &&
                        lm_pin_counter(++record.failures);
        bool valid = prepared && furi_hal_crypto_gcm_decrypt_and_verify(wrapping, record.nonce,
            (const uint8_t*)&record, offsetof(PinRecord, ciphertext), record.ciphertext, key, 32, record.tag)
            == FuriHalCryptoGCMStateOk;
        if(valid) app->vault_state = lm_load(app, NULL, key, record.salt);
        lm_clear(pin, sizeof(pin));
        lm_clear(wrapping, sizeof(wrapping));
        lm_clear(key, sizeof(key));
        if(busy) {
            gui_remove_view_port(gui, busy);
            view_port_free(busy);
        }
        if(!prepared) {
            if(entered) *available = false;
            return false;
        }
        *available = record.failures < LM_PIN_LIMIT;
        if(valid) {
            if(app->vault_state != VaultReady) return false;
            lm_pin_counter(0);
            return true;
        }
        lm_notice(gui, record.failures == LM_PIN_LIMIT ? "Use master password" : "Incorrect PIN");
    }
    return false;
}

static SendStatus lm_start_keyboard(LoginManager* app);

#define LM_LAYOUT_PATH EXT_PATH("apps_data/lockfin/keyboard.cfg")

static bool lm_layout_preference(KeyboardLayout* layout, bool write) {
    Storage* storage = furi_record_open(RECORD_STORAGE);
    File* file = storage_file_alloc(storage);
    uint8_t value = (uint8_t)*layout;
    bool ok;
    if(write) {
        ok = storage_file_open(file, LM_LAYOUT_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS) &&
             storage_file_write(file, &value, 1) == 1 && storage_file_sync(file);
    } else {
        ok = storage_file_open(file, LM_LAYOUT_PATH, FSAM_READ, FSOM_OPEN_EXISTING) &&
             storage_file_size(file) == 1 && storage_file_read(file, &value, 1) == 1 &&
             value < LayoutCount;
        if(ok) *layout = (KeyboardLayout)value;
    }
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
    return ok;
}

static void lm_layout_menu(LoginManager* app, Gui* gui) {
    const char* const labels[] = {"English (US)", "Spanish (Spain)", "Spanish (Latin Am.)"};
    int choice = lm_choice(gui, "Host keyboard layout", labels, COUNT_OF(labels), app->layout);
    if(choice < 0) return;
    app->layout = (KeyboardLayout)choice;
    if(!lm_layout_preference(&app->layout, true)) lm_notice(gui, "Layout for session only");
}

static void lm_connection_menu(LoginManager* app, Gui* gui) {
    const char* const options[] = {"USB", "BLE", "Auto (USB first)", "Reset BLE pairing"};
    int choice = lm_choice(gui, "Connection", options, app->bt_profile ? 4 : 3, app->mode);
    if(choice < 0) return;
    if(choice == 3) {
        const char* const confirm[] = {"Cancel", "Forget Lockfin hosts"};
        if(lm_choice(gui, "Reset keyboard pairing?", confirm, 2, 0) != 1) return;
        bt_disconnect(app->bt);
        furi_delay_ms(200);
        bt_forget_bonded_devices(app->bt);
        /* Disconnect is synchronous and runs after the queued bond reset. */
        bt_disconnect(app->bt);
        lm_stop_ble(app);
    } else if((KeyboardMode)choice != app->mode) {
        lm_stop_keyboard(app);
        app->mode = (KeyboardMode)choice;
    }
    app->status = lm_start_keyboard(app);
    if(app->status == StatusBtUnavailable) lm_notice(gui, "BLE unavailable");
}

static void lm_move_login(StoredLogin* entries, size_t from, size_t to) {
    StoredLogin moved = entries[from];
    if(from < to) memmove(entries + from, entries + from + 1, (to - from) * sizeof(*entries));
    if(from > to) memmove(entries + to + 1, entries + to, (from - to) * sizeof(*entries));
    entries[to] = moved;
}

static void lm_toggle_favorite(LoginManager* app, Gui* gui) {
    size_t from = app->selected;
    size_t old_count = app->favorites;
    bool removing = from < old_count;
    size_t to = removing ? old_count - 1 : old_count;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    lm_move_login(app->logins, from, to);
    app->favorites = removing ? old_count - 1 : old_count + 1;
    furi_mutex_release(app->mutex);
    bool saved = lm_save(app);
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    if(saved) {
        app->selected = app->scroll = to;
    } else {
        lm_move_login(app->logins, to, from);
        app->favorites = old_count;
    }
    furi_mutex_release(app->mutex);
    if(!saved) lm_notice(gui, "Save failed");
}

static void lm_manage(LoginManager* app, Gui* gui) {
    bool entry = app->selected < app->count;
    const char* const choices[] = {app->selected < app->favorites ? "Remove favorite" : "Add favorite",
                                  "Edit login", "Delete login", "Add login",
                                  "Change vault password", "Lock vault", "Set quick PIN", "Remove quick PIN", "Connection", "Keyboard layout", "Controls"};
    int choice = lm_choice(gui, "Manage", choices + (entry ? 0 : 3), COUNT_OF(choices) - (entry ? 0 : 3), 0);
    if(choice < 0) return;
    if(entry && choice == 0) { lm_toggle_favorite(app, gui); return; }
    choice += entry ? -1 : 2;
    if(choice == 0) lm_edit_login(app, gui, false);
    else if(choice == 1) lm_delete_login(app, gui);
    else if(choice == 2) lm_edit_login(app, gui, true);
    else if(choice == 3) lm_change_master(app, gui, false);
    else if(choice == 4) lm_lock(app);
    else if(choice == 5) lm_pin_setup(app, gui);
    else if(choice == 6) {
        Storage* storage = furi_record_open(RECORD_STORAGE);
        bool ok = storage_simply_remove(storage, LM_PIN_PATH);
        furi_record_close(RECORD_STORAGE);
        lm_notice(gui, ok ? "Quick PIN removed" : "Could not remove PIN");
    } else if(choice == 7) lm_connection_menu(app, gui);
    else if(choice == 8) lm_layout_menu(app, gui);
    else if(choice == 9) {
        const char* const help[] = {"OK: open / type", "List Left: A-Z", "Hold OK: manage", "Hold Right: U2F",
                                    "Hold Down: Authenticator", "Back: return"};
        lm_choice(gui, "Controls", help, COUNT_OF(help), 0);
    }
}

/* The attempted password stays in this prompt only until Back, Exit or success.
   Retrying always reopens the file and authenticates it from the supplied master. */
static bool lm_startup_unlock(LoginManager* app, Gui* gui) {
    app->vault_state = lm_probe();
    if(app->vault_state == VaultCryptoError || app->vault_state == VaultBadFormat) {
        lm_notice(gui, app->vault_state == VaultBadFormat ? "Invalid vault file" : "Check SD card");
        return false;
    }
    if(app->vault_state == VaultMissing) {
        const char* const menu[] = {"Create vault"};
        return lm_choice(gui, "Lockfin", menu, 1, 0) == 0 && lm_change_master(app, gui, true);
    }

    bool pin_available = false;
    char master[LM_MASTER_SIZE] = {0};
    bool unlocked = false;
    if(lm_quick_unlock(app, gui, &pin_available)) return true;
    for(;;) {
        if(!lm_prompt(gui, master)) {
            lm_clear(master, sizeof(master));
            if(!pin_available) break;
            const char* const routes[] = {"Quick PIN", "Exit"};
            if(lm_choice(gui, "Unlock with", routes, COUNT_OF(routes), 0) != 0) break;
            if(lm_quick_unlock(app, gui, &pin_available)) {
                unlocked = true;
                break;
            }
            continue;
        }
        app->vault_state = lm_load(app, master, NULL, NULL);
        if(app->vault_state == VaultReady) {
            unlocked = true;
            break;
        }
        if(app->vault_state == VaultBadPassword) {
            const char* const actions[] = {"Edit last entry", "Start over", "Exit"};
            int choice = lm_choice(gui, "Check master password", actions, COUNT_OF(actions), 0);
            if(choice == 0) continue;
            if(choice != 1) break;
        } else {
            const char* const actions[] = {"Retry", "Exit"};
            const char* title = app->vault_state == VaultInteropError ? "Crypto test failed" :
                                app->vault_state == VaultBadFormat ? "Invalid vault file" :
                                "Vault read failed";
            if(lm_choice(gui, title, actions, COUNT_OF(actions), 0) != 0) break;
        }
        lm_clear(master, sizeof(master));
    }
    lm_clear(master, sizeof(master));
    return unlocked;
}

/* El aviso solo se muestra despues de autenticar, por ambas rutas. */
static bool lm_startup(LoginManager* app, Gui* gui) {
    if(!lm_startup_unlock(app, gui)) return false;
    if(app->rounds < LM_KDF_ITERATIONS) {
        char cost[32];
        snprintf(cost, sizeof(cost), "%lu iterations", (unsigned long)app->rounds);
        const char* const items[] = {cost, "Change vault password"};
        lm_choice(gui, "Older KDF: upgrade", items, COUNT_OF(items), 0);
    }
    return true;
}

static void lm_fit(Canvas* canvas, int x, int baseline, unsigned width, const char* text) {
    char label[LM_FIELD_SIZE];
    snprintf(label, sizeof(label), "%s", text);
    size_t length = strlen(label);
    while(length && canvas_string_width(canvas, label) > width) label[--length] = '\0';
    canvas_draw_str(canvas, x, baseline, label);
}

static void lm_button(Canvas* canvas, int x, int y, int width, int height, bool selected) {
    canvas_set_color(canvas, ColorBlack);
    if(selected) {
        canvas_draw_rbox(canvas, x, y, width, height, 3);
        canvas_set_color(canvas, ColorWhite);
    } else {
        canvas_draw_rframe(canvas, x, y, width, height, 3);
    }
}

static const char* lm_action_name(Action action) {
    static const char* const names[] = {"Username", "Password", "Shift+Tab", "Enter", "Tab", "Space"};
    return names[action];
}

static const char* lm_status_name(SendStatus status) {
    switch(status) {
    case StatusSent: return "Sent";
    case StatusSaved: return "Saved";
    case StatusSaveFailed: return "Save failed";
    case StatusUsbBusy: return "USB busy / RPC";
    case StatusNoKeyboard: return "Connect USB or BLE";
    case StatusDisconnected: return "USB not ready";
    case StatusBtWaiting: return "Pair Lockfin on host";
    case StatusBtUnavailable: return "BLE unavailable";
    case StatusEmpty: return "No username";
    case StatusUnsupported: return "Unsupported character";
    case StatusFailed: return "Typing interrupted";
    default: return "";
    }
}

static void lm_horizontal_arrow(Canvas* canvas, int x, int y, int direction) {
    int tip = x + 5 * direction;
    canvas_draw_line(canvas, x - 5 * direction, y, tip, y);
    canvas_draw_line(canvas, tip - 3 * direction, y - 3, tip, y);
    canvas_draw_line(canvas, tip - 3 * direction, y + 3, tip, y);
}

/* Auto also represents "waiting for either" when no keyboard is connected. */
static KeyboardMode lm_route(const LoginManager* app) {
    if(app->mode != KeyboardAuto) return app->mode;
    if(app->owns_usb && furi_hal_hid_is_connected()) return KeyboardUsb;
    if(__atomic_load_n(&app->bt_connected, __ATOMIC_ACQUIRE)) return KeyboardBle;
    return KeyboardAuto;
}

static void lm_draw_details(Canvas* canvas, LoginManager* app) {
    KeyboardMode route = lm_route(app);
    bool connected = __atomic_load_n(&app->bt_connected, __ATOMIC_ACQUIRE);
    const char* transport = route == KeyboardUsb ? "USB" :
                            route == KeyboardAuto ? "USB/BLE" : connected ? "BLE" : "BLE waiting";
    lm_fit(canvas, 3, 8, 118 - canvas_string_width(canvas, transport), app->logins[app->selected].name);
    canvas_draw_str_aligned(canvas, 126, 8, AlignRight, AlignBottom, transport);
    canvas_draw_line(canvas, 0, 10, 127, 10);
    if(app->shortcuts) {
        canvas_draw_str(canvas, 26, 22, "Tap");
        lm_horizontal_arrow(canvas, 58, 18, 1);
        canvas_draw_str(canvas, 73, 22, "Passkeys");
        canvas_draw_str(canvas, 26, 34, "Hold");
        lm_horizontal_arrow(canvas, 58, 30, 1);
        canvas_draw_str(canvas, 73, 34, "U2F");
        canvas_draw_str(canvas, 26, 46, "Hold");
        canvas_draw_line(canvas, 58, 38, 58, 44);
        canvas_draw_line(canvas, 55, 41, 58, 44);
        canvas_draw_line(canvas, 61, 41, 58, 44);
        canvas_draw_str(canvas, 73, 46, "Auth");
        canvas_draw_line(canvas, 3, 50, 124, 50);
        canvas_draw_str(canvas, 3, 63, "OK: USB/BLE");
        canvas_draw_str_aligned(canvas, 111, 63, AlignRight, AlignBottom, "2/2");
        return;
    }

    lm_button(canvas, 12, 12, 28, 15, app->action == ActionUsername);
    canvas_draw_disc(canvas, 26, 16, 2);
    canvas_draw_rbox(canvas, 20, 20, 12, 4, 2);
    lm_button(canvas, 50, 12, 28, 15, app->action == ActionEnter);
    canvas_draw_str_aligned(canvas, 64, 23, AlignCenter, AlignBottom, "OK");
    lm_button(canvas, 88, 12, 28, 15, app->action == ActionPassword);
#ifdef LM_HAS_FIRMWARE_ICONS
    canvas_draw_icon(canvas, 99, 15, &I_Lock_7x8);
#else
    canvas_draw_rframe(canvas, 100, 15, 5, 6, 2);
    canvas_draw_box(canvas, 99, 18, 7, 5);
#endif

    lm_button(canvas, 12, 29, 28, 15, app->action == ActionPrevious);
    lm_horizontal_arrow(canvas, 26, 36, -1);
    lm_button(canvas, 50, 29, 28, 15, app->action == ActionSpace);
    canvas_draw_line(canvas, 57, 34, 57, 38);
    canvas_draw_line(canvas, 57, 38, 71, 38);
    canvas_draw_line(canvas, 71, 38, 71, 34);
    lm_button(canvas, 88, 29, 28, 15, app->action == ActionNext);
    lm_horizontal_arrow(canvas, 102, 36, 1);

    canvas_set_color(canvas, ColorBlack);
    canvas_draw_line(canvas, 54, 47, 54, 53);
    canvas_draw_line(canvas, 51, 50, 54, 53);
    canvas_draw_line(canvas, 57, 50, 54, 53);
    canvas_draw_str(canvas, 61, 54, "1/2");
    char footer[32];
    if(app->sending) {
        snprintf(footer, sizeof(footer), "Working...");
    } else if(app->status != StatusReady && !(app->status == StatusBtWaiting && connected) &&
              !(app->status == StatusNoKeyboard && route != KeyboardAuto)) {
        snprintf(footer, sizeof(footer), "%s", lm_status_name(app->status));
    } else {
        snprintf(footer, sizeof(footer), "OK: %s", lm_action_name(app->action));
    }
    lm_fit(canvas, 3, 63, 109, footer);
}

static char lm_ascii_lower(char c) {
    return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

static bool lm_starts_with(const char* text, const char* lower_prefix) {
    while(*lower_prefix) {
        if(lm_ascii_lower(*text++) != *lower_prefix++) return false;
    }
    return true;
}

/* Format only host-like identifiers. User labels and country domains retain
 * their meaning; details still display the original stored identifier. */
static void lm_site_label(const char* name, char out[LM_FIELD_SIZE]) {
    snprintf(out, LM_FIELD_SIZE, "%s", name);
    const char* host = name;
    if(lm_starts_with(host, "https://")) host += 8;
    else if(lm_starts_with(host, "http://")) host += 7;
    char domain[LM_FIELD_SIZE];
    size_t length = 0;
    bool dot = false;
    while(*host && *host != '/' && *host != '?' && *host != '#') {
        if(*host == '\\' && host[1] == '.') ++host;
        char c = *host++;
        if(c == '.') {
            if(!length || domain[length - 1] == '.') return;
            dot = true;
        } else if(!(c == '-' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9'))) return;
        if(length >= sizeof(domain) - 1) return;
        domain[length++] = c;
    }
    if(!dot || domain[length - 1] == '.') return;
    domain[length] = 0;
    size_t start = length > 4 && lm_starts_with(domain, "www.") ? 4 : 0;
    if(length - start > 4 && lm_starts_with(domain + length - 4, ".com")) length -= 4;
    memcpy(out, domain + start, length - start);
    out[length - start] = 0;
}

static unsigned lm_letter_group(const char* label) {
    char c = lm_ascii_lower(label[0]);
    return c >= 'a' && c <= 'z' ? (unsigned)(c - 'a') + 1 : 0;
}

/* Keep the vault order intact. The stored index also breaks ties between duplicate labels. */
static int lm_compare_rows(const LoginManager* app, size_t a, size_t b) {
    if((a < app->favorites) != (b < app->favorites)) return a < app->favorites ? -1 : 1;
    char left[LM_FIELD_SIZE], right[LM_FIELD_SIZE];
    lm_site_label(app->logins[a].name, left);
    lm_site_label(app->logins[b].name, right);
    int diff = (int)lm_letter_group(left) - (int)lm_letter_group(right);
    for(size_t i = 0; !diff && left[i] && right[i]; ++i) {
        diff = (unsigned char)lm_ascii_lower(left[i]) - (unsigned char)lm_ascii_lower(right[i]);
    }
    if(!diff) diff = (int)strlen(left) - (int)strlen(right);
    return diff ? diff : (int)a - (int)b;
}

static size_t lm_list_row(const LoginManager* app) {
    for(size_t row = 0; row < app->count; ++row) {
        if(app->list_order[row] == app->selected) return row;
    }
    return app->count;
}

static void lm_scroll_to_row(LoginManager* app, size_t row) {
    if(row < app->scroll) app->scroll = row;
    if(row >= app->scroll + LM_VISIBLE_ROWS) app->scroll = row - LM_VISIBLE_ROWS + 1;
}

static void lm_index_list(LoginManager* app, bool select_first) {
    for(size_t i = 0; i < app->count; ++i) app->list_order[i] = i;
    for(size_t gap = app->count / 2; gap; gap /= 2) {
        for(size_t i = gap; i < app->count; ++i) {
            uint16_t entry = app->list_order[i];
            size_t j = i;
            while(j >= gap && lm_compare_rows(app, entry, app->list_order[j - gap]) < 0) {
                app->list_order[j] = app->list_order[j - gap];
                j -= gap;
            }
            app->list_order[j] = entry;
        }
    }
    if(select_first && app->count) app->selected = app->list_order[0];
    lm_scroll_to_row(app, lm_list_row(app));
}

static void lm_jump_to_letter(LoginManager* app, Gui* gui) {
    const char* const alphabet = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    size_t first[27];
    for(size_t i = 0; i < COUNT_OF(first); ++i) first[i] = app->count;
    char label[LM_FIELD_SIZE];
    for(size_t i = 0; i < app->count; ++i) {
        size_t index = app->list_order[i];
        lm_site_label(app->logins[index].name, label);
        unsigned group = lm_letter_group(label);
        if(first[group] == app->count ||
           (first[group] < app->favorites && i >= app->favorites)) first[group] = i;
    }
    lm_clear(label, sizeof(label));
    char names[27][2];
    const char* choices[27];
    size_t rows[27], count = 0;
    for(size_t i = 0; i < COUNT_OF(first); ++i) {
        if(first[i] == app->count) continue;
        names[count][0] = alphabet[i];
        names[count][1] = 0;
        choices[count] = names[count];
        rows[count++] = first[i];
    }
    if(!count) return;
    int choice = lm_choice(gui, "Jump to letter", choices, count, 0);
    if(choice < 0) return;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    app->scroll = rows[choice];
    app->selected = app->list_order[app->scroll];
    furi_mutex_release(app->mutex);
}

static void lm_draw(Canvas* canvas, void* context) {
    LoginManager* app = context;
    furi_mutex_acquire(app->mutex, FuriWaitForever);
    canvas_clear(canvas);
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    if(app->vault_state != VaultReady) {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 3, 10, "Lockfin");
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_line(canvas, 0, 12, 127, 12);
        const char* title = "Vault locked";
        const char* hint = "OK to unlock";
        if(app->vault_state == VaultMissing) {
            title = "Create a vault";
            hint = "OK to set password";
        } else if(app->vault_state == VaultOpening) {
            title = "Opening vault...";
            hint = "Please wait";
        } else if(app->vault_state == VaultBadPassword) {
            title = "Check key or file";
            hint = "or modified file";
        } else if(app->vault_state == VaultBadFormat) {
            title = "Invalid vault";
            hint = "Check vault file";
        } else if(app->vault_state == VaultInteropError) {
            title = "Crypto test failed";
        } else if(app->vault_state == VaultCryptoError) {
            title = "Could not open vault";
            hint = "Memory or crypto error";
        }
        canvas_draw_str(canvas, 3, 29, title);
        lm_fit(canvas, 3, 43, 122, hint);
        if(app->vault_state != VaultOpening) canvas_draw_str(canvas, 3, 63, "OK: open / retry");
    } else if(app->details) {
        lm_draw_details(canvas, app);
    } else {
        canvas_set_font(canvas, FontPrimary);
        canvas_draw_str(canvas, 3, 9, "Lockfin");
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_line(canvas, 0, 11, 127, 11);
        for(size_t row = 0; row < LM_VISIBLE_ROWS; ++row) {
            size_t position = app->scroll + row;
            if(position > app->count) break;
            size_t index = position == app->count ? app->count : app->list_order[position];
            int y = 12 + (int)row * 21;
            if(index == app->selected) {
                canvas_draw_rbox(canvas, 1, y, 126, 21, 2);
                canvas_set_color(canvas, ColorWhite);
            }
            if(index == app->count) {
                lm_fit(canvas, 4, y + 13, 119, "+ Add login");
            } else {
                const StoredLogin* entry = &app->logins[index];
                canvas_set_font(canvas, FontPrimary);
                char site[LM_FIELD_SIZE];
                lm_site_label(entry->name, site);
                bool favorite = index < app->favorites;
                if(favorite) canvas_draw_str(canvas, 4, y + 9, "*");
                lm_fit(canvas, favorite ? 13 : 4, y + 9, favorite ? 110 : 119, site);
                canvas_set_font(canvas, FontSecondary);
                lm_fit(canvas, 7, y + 19, 116, entry->username[0] ? entry->username : "(no username)");
            }
            canvas_set_color(canvas, ColorBlack);
        }
        char count[16];
        snprintf(count, sizeof(count), "%u Login%s", (unsigned)app->count, app->count == 1 ? "" : "s");
        canvas_draw_str_aligned(canvas, 125, 9, AlignRight, AlignBottom, count);
        lm_horizontal_arrow(canvas, 8, 59, 1);
        canvas_draw_str(canvas, 17, 63, "Passkeys");
    }
#ifdef LM_HAS_FIRMWARE_ICONS
    canvas_draw_icon(canvas, 116, 56, &I_Pin_back_arrow_10x8);
#else
    canvas_draw_line(canvas, 117, 59, 124, 59);
    canvas_draw_line(canvas, 124, 59, 124, 62);
    canvas_draw_line(canvas, 117, 59, 120, 56);
    canvas_draw_line(canvas, 117, 59, 120, 62);
#endif
    furi_mutex_release(app->mutex);
}

static void lm_input(InputEvent* event, void* context) {
    LoginManager* app = context;
    if(event->type != InputTypeShort && event->type != InputTypeRepeat &&
       event->type != InputTypeLong) return;

    if(event->type == InputTypeRepeat &&
       (event->key == InputKeyOk || event->key == InputKeyBack)) return;
    if(furi_mutex_acquire(app->mutex, 0) != FuriStatusOk) return;
    bool factor_key = app->details && (event->key == InputKeyRight || event->key == InputKeyDown);
    bool ignore_long = event->type == InputTypeLong && event->key != InputKeyOk && !factor_key;
    bool ignore_repeat = event->type == InputTypeRepeat && factor_key;
    bool sending = app->sending || ignore_long || ignore_repeat;
    furi_mutex_release(app->mutex);
    if(!sending) furi_message_queue_put(app->events, event, 0);
}

static SendStatus lm_usb_start(LoginManager* app) {
    if(app->owns_usb) return StatusReady;
    if(furi_hal_usb_is_locked()) return StatusUsbBusy;
    app->previous_usb = furi_hal_usb_get_config();
    if(!furi_hal_usb_set_config(&usb_hid, NULL)) return StatusUsbBusy;
    app->owns_usb = true;
    return StatusReady;
}

static SendStatus lm_ble_start(LoginManager* app) {
    if(app->bt_profile) return StatusReady;
    if(!furi_hal_bt_is_alive()) return StatusBtUnavailable;
    app->bt = furi_record_open(RECORD_BT);
    bt_disconnect(app->bt);
    furi_delay_ms(200);
    bt_keys_storage_set_storage_path(app->bt, EXT_PATH("apps_data/lockfin/.bt.keys"));
    app->bt_params = (BleProfileHidParams){.device_name_prefix="Lockfin", .mac_xor=0x4c46};
    bt_set_status_changed_callback(app->bt, lm_bt_status, app);
    app->bt_profile = bt_profile_start(app->bt, ble_profile_hid, &app->bt_params);
    if(!app->bt_profile) {
        lm_stop_ble(app);
        return StatusBtUnavailable;
    }
    furi_hal_bt_start_advertising();
    return StatusReady;
}

static SendStatus lm_start_keyboard(LoginManager* app) {
    if(app->mode == KeyboardUsb) return lm_usb_start(app);
    if(app->mode == KeyboardBle) return lm_ble_start(app);
    SendStatus usb = lm_usb_start(app);
    SendStatus ble = lm_ble_start(app);
    return usb == StatusReady ? usb : ble;
}

static bool lm_connected(LoginManager* app, KeyboardMode route) {
    if(route == KeyboardBle) return app->bt_profile && __atomic_load_n(&app->bt_connected, __ATOMIC_ACQUIRE);
    return app->owns_usb && furi_hal_hid_is_connected();
}

static bool lm_release_keys(LoginManager* app, KeyboardMode route) {
    /* Momentum 012 GATT reports true on error. USB HID reports true on success. */
    return route == KeyboardBle ? !ble_profile_hid_kb_release_all(app->bt_profile) : furi_hal_hid_kb_release_all();
}

static bool lm_key(LoginManager* app, KeyboardMode route, uint16_t key) {
    if(!lm_connected(app, route)) return false;
    bool pressed = route == KeyboardBle ? !ble_profile_hid_kb_press(app->bt_profile, key) : furi_hal_hid_kb_press(key);
    uint32_t delay = route == KeyboardBle ? 30 : 15;
    if(pressed) furi_delay_ms(delay);
    bool released = lm_release_keys(app, route);
    furi_delay_ms(delay);
    return pressed && released && lm_connected(app, route);
}

/* HID usages for printable ASCII on standard PC Spanish layouts. Zero uses
   the SDK US mapping. A dead key needs a following space to commit it. */
#define LM_DEAD_KEY 0x8000u
static uint16_t lm_layout_key(KeyboardLayout layout, unsigned char ch) {
    if(ch < 32 || ch > 126) return HID_KEYBOARD_NONE;
    static const struct { char ch; uint16_t spain, latam; } overrides[] = {
        {'"', 0x021f, 0x021f},
        {'#', 0x4020, 0x0000},
        {'&', 0x0223, 0x0223},
        {'\'', 0x002d, 0x002d},
        {'(', 0x0225, 0x0225},
        {')', 0x0226, 0x0226},
        {'*', 0x0230, 0x0230},
        {'+', 0x0030, 0x0030},
        {'-', 0x0038, 0x0038},
        {'/', 0x0224, 0x0224},
        {':', 0x0237, 0x0237},
        {';', 0x0236, 0x0236},
        {'<', 0x0064, 0x0064},
        {'=', 0x0227, 0x0227},
        {'>', 0x0264, 0x0264},
        {'?', 0x022d, 0x022d},
        {'@', 0x401f, 0x4014},
        {'[', 0x4025, 0x0234},
        {'\\', 0x402d, 0x402d},
        {']', 0x4026, 0x0231},
        {'^', 0x822f, 0xc034},
        {'_', 0x0238, 0x0238},
        {'`', 0x802f, 0xc031},
        {'{', 0x4024, 0x0034},
        {'|', 0x401e, 0x0035},
        {'}', 0x4027, 0x0031},
        {'~', 0x4021, 0x4021},
    };
    if(layout != LayoutUS) {
        for(size_t i = 0; i < COUNT_OF(overrides); ++i) {
            if(overrides[i].ch != ch) continue;
            uint16_t key = layout == LayoutSpain ? overrides[i].spain : overrides[i].latam;
            if(key) return key;
            break;
        }
    }
    return HID_ASCII_TO_KEY(ch);
}

static SendStatus lm_send(LoginManager* app, Action action, const char* text) {
    if(action == ActionUsername || action == ActionPassword) {
        if(!*text) return StatusEmpty;
        for(const unsigned char* p = (const unsigned char*)text; *p; ++p) {
            if(!lm_layout_key(app->layout, *p)) {
                return StatusUnsupported;
            }
        }
    }
    if(!app->owns_usb && !app->bt_profile) {
        SendStatus status = lm_start_keyboard(app);
        if(status != StatusReady) return status;
    }
    /* Pin this action to one host, including its final key release. */
    KeyboardMode route = lm_route(app);
    if(route == KeyboardAuto) return StatusNoKeyboard;
    if(!lm_connected(app, route)) return route == KeyboardBle ? StatusBtWaiting : StatusDisconnected;

    bool success = true;
    if(action == ActionUsername || action == ActionPassword) {
        for(const unsigned char* p = (const unsigned char*)text; *p; ++p) {
            uint16_t key = lm_layout_key(app->layout, *p);
            if(!lm_key(app, route, key & ~LM_DEAD_KEY) ||
               ((key & LM_DEAD_KEY) && !lm_key(app, route, HID_KEYBOARD_SPACEBAR))) {
                success = false;
                break;
            }
        }
    } else {
        uint16_t key = action == ActionEnter ? HID_KEYBOARD_RETURN : HID_KEYBOARD_TAB;
        if(action == ActionSpace) key = HID_KEYBOARD_SPACEBAR;
        if(action == ActionPrevious) key |= KEY_MOD_LEFT_SHIFT;
        success = lm_key(app, route, key);
    }
    lm_release_keys(app, route);
    return success ? StatusSent : StatusFailed;
}

static Action lm_move(Action current, InputKey key) {
    /* Columns: up, down, left, right. Navigation never sends PC keystrokes. */
    static const Action moves[ActionCount][4] = {
        [ActionUsername] = {ActionUsername, ActionPrevious, ActionUsername, ActionEnter},
        [ActionEnter] = {ActionEnter, ActionSpace, ActionUsername, ActionPassword},
        [ActionPassword] = {ActionPassword, ActionNext, ActionEnter, ActionPassword},
        [ActionPrevious] = {ActionUsername, ActionPrevious, ActionPrevious, ActionSpace},
        [ActionSpace] = {ActionEnter, ActionSpace, ActionPrevious, ActionNext},
        [ActionNext] = {ActionPassword, ActionNext, ActionSpace, ActionNext},
    };
    switch(key) {
    case InputKeyUp: return moves[current][0];
    case InputKeyDown: return moves[current][1];
    case InputKeyLeft: return moves[current][2];
    case InputKeyRight: return moves[current][3];
    default: return current;
    }
}

/* Queue the second factor and then this app. Loader starts the next item
 * after normal teardown, including HID restoration and vault memory wipe. */
/* Only the loader receives the encrypted return ticket. Its one-use random
 * wrapping key lives in a firmware RAM record across the two FAP lifetimes. */
#define LM_RETURN_RECORD "lockfin.return.v1"
#define LM_RETURN_PREFIX "lf1:"
typedef struct {
    uint8_t vault_key[32], salt[16], file_tag[16];
    uint16_t row;
    uint8_t action, mode, details, shortcuts;
} ReturnState;
typedef struct {
    uint8_t nonce[12], encrypted[sizeof(ReturnState)], tag[16];
} ReturnTicket;
#define LM_RETURN_ARG_SIZE (sizeof(LM_RETURN_PREFIX) + 2 * sizeof(ReturnTicket))

static int lm_hex_digit(char c) {
    if(c >= '0' && c <= '9') return c-'0';
    if(c >= 'a' && c <= 'f') return c-'a'+10;
    return -1;
}

static bool lm_prepare_return(LoginManager* app, char* argument) {
    if(!app->session_key_ready || app->selected > app->count ||
       furi_record_exists(LM_RETURN_RECORD)) return false;
    ReturnState state = {.row = app->selected, .action = app->action, .mode = app->mode,
                         .details = app->details, .shortcuts = app->shortcuts};
    memcpy(state.vault_key, app->session_key, sizeof(state.vault_key));
    memcpy(state.salt, app->salt, sizeof(state.salt));
    memcpy(state.file_tag, app->saved_tag, sizeof(state.file_tag));
    ReturnTicket ticket;
    uint8_t* wrapping = malloc(32);
    if(!wrapping) { lm_clear(&state, sizeof(state)); return false; }
    furi_hal_random_fill_buf(wrapping, 32);
    furi_hal_random_fill_buf(ticket.nonce, sizeof(ticket.nonce));
    bool ok = furi_hal_crypto_gcm_encrypt_and_tag(wrapping, ticket.nonce,
        (const uint8_t*)LM_RETURN_PREFIX, sizeof(LM_RETURN_PREFIX)-1,
        (const uint8_t*)&state, ticket.encrypted, sizeof(state), ticket.tag)
        == FuriHalCryptoGCMStateOk;
    lm_clear(&state, sizeof(state));
    if(ok) {
        strcpy(argument, LM_RETURN_PREFIX);
        char* out = argument + sizeof(LM_RETURN_PREFIX)-1;
        const uint8_t* raw = (const uint8_t*)&ticket;
        const char hex[] = "0123456789abcdef";
        for(size_t i = 0; i < sizeof(ticket); i++) {
            *out++ = hex[raw[i] >> 4];
            *out++ = hex[raw[i] & 15];
        }
        *out = 0;
        furi_record_create(LM_RETURN_RECORD, wrapping);
    } else {
        lm_clear(wrapping, 32);
        free(wrapping);
    }
    return ok;
}

static bool lm_resume(LoginManager* app, const char* argument) {
    if(!furi_record_exists(LM_RETURN_RECORD)) return false;
    uint8_t* stored = furi_record_open(LM_RETURN_RECORD);
    _Alignas(4) uint8_t wrapping[32];
    memcpy(wrapping, stored, sizeof(wrapping));
    lm_clear(stored, sizeof(wrapping));
    furi_record_close(LM_RETURN_RECORD);
    bool removed = furi_record_destroy(LM_RETURN_RECORD);
    if(removed) free(stored);
    ReturnTicket ticket;
    ReturnState state = {0};
    bool ok = false;
    if(!removed || !argument || strlen(argument) != LM_RETURN_ARG_SIZE-1 ||
       strncmp(argument, LM_RETURN_PREFIX, sizeof(LM_RETURN_PREFIX)-1)) goto done;
    const char* in = argument + sizeof(LM_RETURN_PREFIX)-1;
    for(size_t i = 0; i < sizeof(ticket); i++) {
        int a = lm_hex_digit(*in++), b = lm_hex_digit(*in++);
        if(a < 0 || b < 0) goto done;
        ((uint8_t*)&ticket)[i] = (uint8_t)((a << 4) | b);
    }
    if(furi_hal_crypto_gcm_decrypt_and_verify(wrapping, ticket.nonce,
            (const uint8_t*)LM_RETURN_PREFIX, sizeof(LM_RETURN_PREFIX)-1, ticket.encrypted,
            (uint8_t*)&state, sizeof(state), ticket.tag) != FuriHalCryptoGCMStateOk ||
       state.action >= ActionCount || state.mode > KeyboardAuto) goto done;
    if(lm_load(app, NULL, state.vault_key, state.salt) != VaultReady) goto done;
    if(memcmp(state.file_tag, app->saved_tag, 16) || state.row > app->count ||
       (state.details && state.row == app->count)) {
        lm_lock(app);
        goto done;
    }
    app->vault_state = VaultReady;
    app->selected = state.row;
    app->scroll = state.row;
    app->mode = state.mode;
    app->action = (Action)state.action;
    app->details = state.details;
    app->shortcuts = state.details && state.shortcuts;
    ok = true;
done:
    lm_clear(wrapping, sizeof(wrapping));
    lm_clear(&state, sizeof(state));
    return ok;
}

typedef enum { FactorU2f, FactorTotp, FactorPasskeys } LoginFactor;

static bool lm_launch_factor(LoginManager* app, Gui* gui, LoginFactor factor) {
    const char* target = "U2F";
    if(factor != FactorU2f) {
        target = factor == FactorPasskeys ? EXT_PATH("apps/USB/fido2_security_key.fap") :
                                            EXT_PATH("apps/Tools/totp.fap");
        Storage* storage = furi_record_open(RECORD_STORAGE);
        bool installed = storage_file_exists(storage, target);
        furi_record_close(RECORD_STORAGE);
        if(!installed) {
            lm_notice(gui, factor == FactorPasskeys ? "Install FIDO2 in USB" : "Install Authenticator");
            return false;
        }
    }
    Loader* loader = furi_record_open(RECORD_LOADER);
    FuriString* self = furi_string_alloc();
    bool found = loader_get_application_launch_path(loader, self);
    if(found) {
        char argument[LM_RETURN_ARG_SIZE];
        bool resume = lm_prepare_return(app, argument);
        loader_enqueue_launch(loader, target, NULL, LoaderDeferredLaunchFlagGui);
        loader_enqueue_launch(loader, furi_string_get_cstr(self), resume ? argument : NULL, LoaderDeferredLaunchFlagGui);
    }
    furi_string_free(self);
    furi_record_close(RECORD_LOADER);
    if(!found) lm_notice(gui, "Launcher unavailable");
    return found;
}

int32_t login_manager_app(void* context) {
    LoginManager* app = calloc(1, sizeof(LoginManager));
    furi_check(app);
    app->mode = KeyboardAuto;
    lm_layout_preference(&app->layout, false);
    app->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    app->events = furi_message_queue_alloc(8, sizeof(InputEvent));
    app->viewport = view_port_alloc();
    furi_check(app->mutex && app->events && app->viewport);
    Gui* gui = furi_record_open(RECORD_GUI);
    view_port_draw_callback_set(app->viewport, lm_draw, app);
    view_port_input_callback_set(app->viewport, lm_input, app);
    bool resumed = lm_resume(app, context);
    bool running = resumed || lm_startup(app, gui);
    bool attached = running;
    if(attached) {
        lm_index_list(app, !resumed);
        app->status = lm_start_keyboard(app);
        gui_add_view_port(gui, app->viewport, GuiLayerFullscreen);
    }
    while(running) {
        InputEvent event;
        if(furi_message_queue_get(app->events, &event, app->mode != KeyboardUsb ? furi_ms_to_ticks(500) : FuriWaitForever) != FuriStatusOk) {
            if(app->mode == KeyboardAuto && !app->owns_usb && !furi_hal_usb_is_locked()) {
                furi_mutex_acquire(app->mutex, FuriWaitForever);
                lm_usb_start(app);
                furi_mutex_release(app->mutex);
            }
            view_port_update(app->viewport);
            continue;
        }
        bool send = false;
        bool unlock = false;
        bool create = false;
        bool add = false;
        bool manage = false;
        bool jump = false;
        bool launch_factor = false;
        LoginFactor factor = FactorU2f;
        bool connection = false;
        Action action = ActionUsername;
        char text[LM_FIELD_SIZE] = {0};
        furi_mutex_acquire(app->mutex, FuriWaitForever);
        if(event.key == InputKeyBack) {
            if(app->shortcuts) {
                app->shortcuts = false;
            } else if(app->details) {
                app->details = false;
                app->status = StatusReady;
            } else {
                running = false;
            }
        } else if(app->vault_state != VaultReady) {
            if(event.key == InputKeyOk) {
                create = app->vault_state == VaultMissing;
                unlock = !create;
            }
        } else if(event.key == InputKeyOk && event.type == InputTypeLong) {
            manage = true;
        } else if(app->details && event.type == InputTypeLong &&
                  (event.key == InputKeyRight || event.key == InputKeyDown)) {
            factor = event.key == InputKeyDown ? FactorTotp : FactorU2f;
            launch_factor = true;
        } else if((!app->details || app->shortcuts) && event.key == InputKeyRight &&
                  event.type == InputTypeShort) {
            factor = FactorPasskeys;
            launch_factor = true;
        } else if(app->details && app->shortcuts) {
            if(event.key == InputKeyUp) app->shortcuts = false;
            if(event.key == InputKeyOk) connection = true;
        } else if(app->details) {
            if(event.key == InputKeyOk) {
                send = true;
                action = app->action;
                const StoredLogin* login = &app->logins[app->selected];
                if(action == ActionUsername || action == ActionPassword) {
                    snprintf(
                        text,
                        sizeof(text),
                        "%s",
                        action == ActionUsername ? login->username : login->password);
                }
                app->sending = true;
                furi_message_queue_reset(app->events);
            } else {
                Action next = lm_move(app->action, event.key);
                if(event.key == InputKeyDown && next == app->action) app->shortcuts = true;
                app->action = next;
                app->status = StatusReady;
            }
        } else {
            if(event.key == InputKeyOk) {
                if(app->selected == app->count) {
                    add = true;
                } else {
                    app->details = true;
                    app->action = ActionUsername;
                    app->status = StatusReady;
                }
            } else if(event.key == InputKeyLeft && event.type == InputTypeShort && app->count) {
                jump = true;
            } else if(event.key == InputKeyUp || event.key == InputKeyDown) {
                size_t row = lm_list_row(app);
                if(event.key == InputKeyUp && row) --row;
                if(event.key == InputKeyDown && row < app->count) ++row;
                app->selected = row == app->count ? app->count : app->list_order[row];
                lm_scroll_to_row(app, row);
            }
        }
        furi_mutex_release(app->mutex);
        view_port_update(app->viewport);

        if(jump) {
            view_port_enabled_set(app->viewport, false);
            lm_jump_to_letter(app, gui);
            furi_message_queue_reset(app->events);
            view_port_enabled_set(app->viewport, true);
            view_port_update(app->viewport);
        }

        if(launch_factor) {
            view_port_enabled_set(app->viewport, false);
            if(lm_launch_factor(app, gui, factor)) break;
            furi_message_queue_reset(app->events);
            view_port_enabled_set(app->viewport, true);
            continue;
        }

        if(create || add || manage || connection) {
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            app->sending = true;
            furi_mutex_release(app->mutex);
            view_port_enabled_set(app->viewport, false);
            if(connection) {
                lm_connection_menu(app, gui);
            } else if(create) {
                lm_change_master(app, gui, true);
            } else if(add) {
                lm_edit_login(app, gui, true);
            } else {
                lm_manage(app, gui);
            }
            bool reopening = app->vault_state != VaultReady;
            if(reopening) {
                running = lm_startup(app, gui);
                if(running) app->status = lm_start_keyboard(app);
            }
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            if(!connection && app->vault_state == VaultReady) lm_index_list(app, reopening);
            app->sending = false;
            furi_mutex_release(app->mutex);
            furi_message_queue_reset(app->events);
            view_port_enabled_set(app->viewport, true);
            view_port_update(app->viewport);
        }

        if(unlock) {
            VaultState state = lm_probe();
            if(state == VaultLocked) {
                char master[LM_MASTER_SIZE] = {0};
                view_port_enabled_set(app->viewport, false);
                bool accepted = lm_prompt(gui, master);
                furi_mutex_acquire(app->mutex, FuriWaitForever);
                app->vault_state = accepted ? VaultOpening : VaultLocked;
                app->sending = accepted;
                furi_mutex_release(app->mutex);
                view_port_enabled_set(app->viewport, true);
                view_port_update(app->viewport);
                if(accepted) {
                    state = lm_load(app, master, NULL, NULL);
                    lm_clear(master, sizeof(master));
                    SendStatus usb_status = state == VaultReady ? lm_start_keyboard(app) : StatusReady;
                    furi_mutex_acquire(app->mutex, FuriWaitForever);
                    if(state == VaultReady) lm_index_list(app, true);
                    app->vault_state = state;
                    app->status = usb_status;
                    app->sending = false;
                    furi_mutex_release(app->mutex);
                }
                lm_clear(master, sizeof(master));
            } else {
                furi_mutex_acquire(app->mutex, FuriWaitForever);
                app->vault_state = state;
                furi_mutex_release(app->mutex);
            }
            furi_message_queue_reset(app->events);
            view_port_update(app->viewport);
        }

        if(send) {
            SendStatus status = lm_send(app, action, text);
            lm_clear(text, sizeof(text));
            furi_mutex_acquire(app->mutex, FuriWaitForever);
            app->status = status;
            app->sending = false;
            furi_mutex_release(app->mutex);
            view_port_update(app->viewport);
        }
    }

    view_port_enabled_set(app->viewport, false);
    if(attached) gui_remove_view_port(gui, app->viewport);
    view_port_free(app->viewport);
    furi_record_close(RECORD_GUI);
    lm_stop_keyboard(app);
    furi_message_queue_free(app->events);
    furi_mutex_free(app->mutex);
    lm_release_logins(app);
    lm_clear(app, sizeof(*app));
    free(app);
    return 0;
}
