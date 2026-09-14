import os
import json
import base64
import hashlib
import tempfile

from kivy.app import App
from kivy.core.window import Window
from kivy.metrics import dp, sp
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.popup import Popup
from kivy.uix.widget import Widget
from kivy.graphics import Color, RoundedRectangle
from kivy.clock import Clock
from kivy.properties import BooleanProperty

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# APP VERSION
# ============================================================

__version__ = "1.0.0"


# ============================================================
# MOBILE KEYBOARD
# ============================================================

Window.softinput_mode = "below_target"


# ============================================================
# ENCRYPTION SETTINGS
# ============================================================

DEFAULT_EXTENSION = ".enc"

PBKDF2_ITERATIONS = 600_000
KEY_LENGTH = 32
SALT_LENGTH = 16
NONCE_LENGTH = 12


# ============================================================
# UI COLORS
# ============================================================

BG_COLOR = (0.06, 0.07, 0.09, 1)
CARD_COLOR = (0.11, 0.12, 0.15, 1)
INPUT_COLOR = (0.08, 0.09, 0.12, 1)

WHITE = (0.95, 0.95, 0.97, 1)
GRAY = (0.65, 0.67, 0.72, 1)

BLUE = (0.20, 0.45, 0.95, 1)
GREEN = (0.20, 0.70, 0.35, 1)
RED = (0.85, 0.20, 0.20, 1)
DISABLED = (0.25, 0.26, 0.30, 1)


# ============================================================
# ANDROID DETECTION
# ============================================================

IS_ANDROID = False

try:
    from android import activity
    from jnius import autoclass

    IS_ANDROID = True

except Exception:
    activity = None


# ============================================================
# UI HELPERS
# ============================================================

def make_label(
    text="",
    size=16,
    color=WHITE,
    bold=False,
    halign="left"
):
    label = Label(
        text=text,
        font_size=sp(size),
        color=color,
        bold=bold,
        size_hint_y=None,
        halign=halign,
        valign="middle"
    )

    label.bind(
        size=lambda inst, val:
        setattr(inst, "text_size", (val[0], None))
    )

    label.bind(
        texture_size=lambda inst, val:
        setattr(inst, "height", max(dp(28), val[1]))
    )

    return label


def make_button(
    text,
    callback,
    color=BLUE,
    height=dp(48)
):
    button = Button(
        text=text,
        font_size=sp(14),
        color=WHITE,
        size_hint_y=None,
        height=height,
        background_normal="",
        background_down="",
        background_color=color
    )

    button.bind(on_release=callback)

    return button


def make_input(
    text="",
    password=False,
    multiline=False,
    hint=""
):
    field = TextInput(
        text=text,
        hint_text=hint,
        hint_text_color=(0.45, 0.47, 0.52, 1),
        font_size=sp(15),
        foreground_color=WHITE,
        background_color=INPUT_COLOR,
        cursor_color=WHITE,
        padding=[dp(12), dp(10)],
        size_hint_y=None,
        height=dp(48),
        multiline=multiline,
        password=password
    )

    return field


# ============================================================
# CRYPTOGRAPHY
# ============================================================

def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_LENGTH
    )


def encrypt_to_bytes(data: list, password: str) -> bytes:
    plaintext = json.dumps(
        data,
        ensure_ascii=False,
        indent=2
    ).encode("utf-8")

    salt = os.urandom(SALT_LENGTH)
    nonce = os.urandom(NONCE_LENGTH)

    key = derive_key(password, salt)

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        plaintext,
        None
    )

    package = {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "data": base64.b64encode(ciphertext).decode("ascii")
    }

    return json.dumps(
        package,
        indent=2
    ).encode("utf-8")


def decrypt_from_bytes(raw: bytes, password: str) -> list:

    package = json.loads(
        raw.decode("utf-8")
    )

    if package.get("version") != 1:
        raise ValueError(
            "Unsupported encrypted file version."
        )

    if package.get("algorithm") != "AES-256-GCM":
        raise ValueError(
            "Unsupported encryption algorithm."
        )

    if package.get("kdf") != "PBKDF2-HMAC-SHA256":
        raise ValueError(
            "Unsupported key derivation function."
        )

    salt = base64.b64decode(
        package["salt"]
    )

    nonce = base64.b64decode(
        package["nonce"]
    )

    ciphertext = base64.b64decode(
        package["data"]
    )

    key = derive_key(
        password,
        salt
    )

    aes = AESGCM(key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        None
    )

    data = json.loads(
        plaintext.decode("utf-8")
    )

    if not isinstance(data, list):
        raise ValueError(
            "Invalid vault format."
        )

    return data


# ============================================================
# NATIVE FILE MANAGER
# ============================================================

class NativeFileManager:

    REQUEST_OPEN = 7001
    REQUEST_CREATE = 7002

    def __init__(self, app):

        self.app = app
        self.pending_action = None

        if IS_ANDROID and activity:

            try:
                activity.bind(
                    on_activity_result=self.on_activity_result
                )

            except Exception as e:
                print(
                    "Activity bind error:",
                    e
                )

    # --------------------------------------------------------
    # OPEN FILE
    # --------------------------------------------------------

    def open_file(self, callback):

        if not IS_ANDROID:
            self.desktop_open_file(callback)
            return

        self.pending_action = (
            "open",
            callback
        )

        try:

            Intent = autoclass(
                "android.content.Intent"
            )

            intent = Intent(
                Intent.ACTION_OPEN_DOCUMENT
            )

            intent.addCategory(
                Intent.CATEGORY_OPENABLE
            )

            intent.setType(
                "application/octet-stream"
            )

            intent.addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION
            )

            intent.addFlags(
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )

            intent.addFlags(
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
            )

            activity.startActivityForResult(
                intent,
                self.REQUEST_OPEN
            )

        except Exception as e:

            self.pending_action = None

            Clock.schedule_once(
                lambda dt:
                callback(None, None, str(e)),
                0
            )

    # --------------------------------------------------------
    # CREATE FILE
    # --------------------------------------------------------

    def create_file(
        self,
        filename,
        data,
        password,
        callback
    ):

        if not filename.lower().endswith(
            DEFAULT_EXTENSION
        ):
            filename += DEFAULT_EXTENSION

        if not IS_ANDROID:

            self.desktop_save_file(
                filename,
                data,
                password,
                callback
            )

            return

        self.pending_action = (
            "create",
            callback,
            data,
            password
        )

        try:

            Intent = autoclass(
                "android.content.Intent"
            )

            intent = Intent(
                Intent.ACTION_CREATE_DOCUMENT
            )

            intent.addCategory(
                Intent.CATEGORY_OPENABLE
            )

            intent.setType(
                "application/octet-stream"
            )

            intent.putExtra(
                Intent.EXTRA_TITLE,
                filename
            )

            intent.addFlags(
                Intent.FLAG_GRANT_READ_URI_PERMISSION
            )

            intent.addFlags(
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION
            )

            intent.addFlags(
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION
            )

            activity.startActivityForResult(
                intent,
                self.REQUEST_CREATE
            )

        except Exception as e:

            self.pending_action = None

            Clock.schedule_once(
                lambda dt:
                callback(None, str(e)),
                0
            )

    # --------------------------------------------------------
    # SHARE FILE
    # --------------------------------------------------------

    def share_file(
        self,
        data,
        password
    ):

        try:

            encrypted = encrypt_to_bytes(
                data,
                password
            )

            # ------------------------------------------------
            # ANDROID
            # ------------------------------------------------

            if IS_ANDROID:

                PythonActivity = autoclass(
                    "org.kivy.android.PythonActivity"
                )

                currentActivity = (
                    PythonActivity.mActivity
                )

                cache_dir = (
                    currentActivity
                    .getCacheDir()
                    .getAbsolutePath()
                )

                temp_path = os.path.join(
                    cache_dir,
                    f"ExportedVault{DEFAULT_EXTENSION}"
                )

                with open(
                    temp_path,
                    "wb"
                ) as f:
                    f.write(encrypted)

                File = autoclass(
                    "java.io.File"
                )

                Intent = autoclass(
                    "android.content.Intent"
                )

                FileProvider = autoclass(
                    "androidx.core.content.FileProvider"
                )

                file_obj = File(
                    temp_path
                )

                app_package = (
                    currentActivity
                    .getPackageName()
                )

                authority = (
                    f"{app_package}.fileprovider"
                )

                uri = FileProvider.getUriForFile(
                    currentActivity,
                    authority,
                    file_obj
                )

                share_intent = Intent(
                    Intent.ACTION_SEND
                )

                share_intent.setType(
                    "application/octet-stream"
                )

                share_intent.putExtra(
                    Intent.EXTRA_STREAM,
                    uri
                )

                share_intent.addFlags(
                    Intent.FLAG_GRANT_READ_URI_PERMISSION
                )

                chooser = Intent.createChooser(
                    share_intent,
                    "Share Vault File"
                )

                currentActivity.startActivity(
                    chooser
                )

            # ------------------------------------------------
            # DESKTOP
            # ------------------------------------------------

            else:

                from plyer import share

                temp_path = os.path.join(
                    tempfile.gettempdir(),
                    f"ExportedVault{DEFAULT_EXTENSION}"
                )

                with open(
                    temp_path,
                    "wb"
                ) as f:
                    f.write(encrypted)

                share.send(
                    path=temp_path
                )

        except Exception as e:

            self.app.show_message(
                "Share Error",
                f"Could not share file:\n{str(e)}"
            )

    # --------------------------------------------------------
    # WRITE TO EXISTING URI
    # --------------------------------------------------------

    def write_to_uri(
        self,
        uri_str,
        data,
        password
    ):

        if not uri_str:
            return False

        try:

            encrypted = encrypt_to_bytes(
                data,
                password
            )

            # Android SAF URI
            if (
                IS_ANDROID
                and uri_str.startswith("content://")
            ):

                Uri = autoclass(
                    "android.net.Uri"
                )

                PythonActivity = autoclass(
                    "org.kivy.android.PythonActivity"
                )

                resolver = (
                    PythonActivity
                    .mActivity
                    .getContentResolver()
                )

                uri = Uri.parse(
                    uri_str
                )

                stream = None

                try:

                    stream = resolver.openOutputStream(
                        uri,
                        "w"
                    )

                    if stream is None:
                        raise IOError(
                            "Could not open output stream."
                        )

                    stream.write(
                        encrypted
                    )

                    stream.flush()

                finally:

                    if stream is not None:

                        try:
                            stream.close()
                        except Exception:
                            pass

            # Desktop path
            else:

                with open(
                    uri_str,
                    "wb"
                ) as f:

                    f.write(
                        encrypted
                    )

            return True

        except Exception as e:

            print(
                "Write Error:",
                e
            )

            return False

    # --------------------------------------------------------
    # ANDROID ACTIVITY RESULT
    # --------------------------------------------------------

    def on_activity_result(
        self,
        request_code,
        result_code,
        intent
    ):

        # Ignore activity results that do not belong
        # to our file picker.
        if request_code not in (
            self.REQUEST_OPEN,
            self.REQUEST_CREATE
        ):
            return

        pending = self.pending_action

        # Clear immediately so callbacks cannot accidentally
        # reuse an old request.
        self.pending_action = None

        Activity = autoclass(
            "android.app.Activity"
        )

        # User cancelled the picker.
        if (
            result_code != Activity.RESULT_OK
            or intent is None
        ):
            return

        try:

            uri = intent.getData()

            if uri is None:
                raise ValueError(
                    "No file was selected."
                )

            uri_str = uri.toString()

            PythonActivity = autoclass(
                "org.kivy.android.PythonActivity"
            )

            resolver = (
                PythonActivity
                .mActivity
                .getContentResolver()
            )

            # ------------------------------------------------
            # OPEN EXISTING FILE
            # ------------------------------------------------

            if request_code == self.REQUEST_OPEN:

                # Try to persist the URI permission.
                try:

                    Intent = autoclass(
                        "android.content.Intent"
                    )

                    take_flags = (
                        intent.getFlags()
                        & (
                            Intent.FLAG_GRANT_READ_URI_PERMISSION
                            | Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                        )
                    )

                    if take_flags != 0:

                        resolver.takePersistableUriPermission(
                            uri,
                            take_flags
                        )

                except Exception as pe:

                    print(
                        "Persistable URI notice:",
                        pe
                    )

                input_stream = None

                try:

                    input_stream = (
                        resolver.openInputStream(uri)
                    )

                    if input_stream is None:
                        raise IOError(
                            "Could not open selected file."
                        )

                    raw = self.read_stream(
                        input_stream
                    )

                finally:

                    if input_stream is not None:

                        try:
                            input_stream.close()
                        except Exception:
                            pass

                if pending:

                    cb = pending[1]

                    Clock.schedule_once(
                        lambda dt:
                        cb(raw, uri_str),
                        0
                    )

            # ------------------------------------------------
            # CREATE NEW FILE
            # ------------------------------------------------

            elif request_code == self.REQUEST_CREATE:

                if pending:

                    cb = pending[1]
                    data = pending[2]
                    password = pending[3]

                    encrypted = encrypt_to_bytes(
                        data,
                        password
                    )

                    output_stream = None

                    try:

                        output_stream = (
                            resolver.openOutputStream(
                                uri,
                                "w"
                            )
                        )

                        if output_stream is None:
                            raise IOError(
                                "Could not open output stream."
                            )

                        output_stream.write(
                            encrypted
                        )

                        output_stream.flush()

                    finally:

                        if output_stream is not None:

                            try:
                                output_stream.close()
                            except Exception:
                                pass

                    Clock.schedule_once(
                        lambda dt:
                        cb(uri_str),
                        0
                    )

        except Exception as e:

            if pending:

                cb = pending[1]

                # OPEN callback:
                # callback(raw, uri, error)
                if request_code == self.REQUEST_OPEN:

                    Clock.schedule_once(
                        lambda dt:
                        cb(None, None, str(e)),
                        0
                    )

                # CREATE callback:
                # callback(uri, error)
                elif request_code == self.REQUEST_CREATE:

                    Clock.schedule_once(
                        lambda dt:
                        cb(None, str(e)),
                        0
                    )

    # --------------------------------------------------------
    # READ JAVA INPUT STREAM
    # --------------------------------------------------------

    @staticmethod
    def read_stream(stream):

        result = bytearray()

        buffer = bytearray(
            8192
        )

        while True:

            count = stream.read(
                buffer
            )

            if count <= 0:
                break

            result.extend(
                buffer[:count]
            )

        return bytes(result)

    # ========================================================
    # DESKTOP FILE OPEN
    # ========================================================

    def desktop_open_file(
        self,
        callback
    ):

        from kivy.uix.filechooser import (
            FileChooserListView
        )

        root = BoxLayout(
            orientation="vertical",
            padding=dp(10),
            spacing=dp(10)
        )

        chooser = FileChooserListView(
            path=os.path.expanduser("~"),
            filters=["*.enc"]
        )

        root.add_widget(
            chooser
        )

        buttons = BoxLayout(
            size_hint_y=None,
            height=dp(48),
            spacing=dp(8)
        )

        popup = Popup(
            title="Select File",
            content=root,
            size_hint=(0.9, 0.8)
        )

        def open_selected(*args):

            if not chooser.selection:
                return

            path = chooser.selection[0]

            try:

                with open(
                    path,
                    "rb"
                ) as f:

                    raw = f.read()

                popup.dismiss()

                callback(
                    raw,
                    path
                )

            except Exception as e:

                popup.dismiss()

                callback(
                    None,
                    path,
                    str(e)
                )

        buttons.add_widget(
            make_button(
                "Cancel",
                lambda x: popup.dismiss(),
                RED
            )
        )

        buttons.add_widget(
            make_button(
                "Open",
                open_selected,
                GREEN
            )
        )

        root.add_widget(
            buttons
        )

        popup.open()

    # ========================================================
    # DESKTOP FILE SAVE
    # ========================================================

    def desktop_save_file(
        self,
        filename,
        data,
        password,
        callback
    ):

        from kivy.uix.filechooser import (
            FileChooserListView
        )

        root = BoxLayout(
            orientation="vertical",
            padding=dp(10),
            spacing=dp(10)
        )

        chooser = FileChooserListView(
            path=os.path.expanduser("~"),
            dirselect=True
        )

        root.add_widget(
            chooser
        )

        name_input = make_input(
            filename,
            hint="Filename"
        )

        root.add_widget(
            name_input
        )

        buttons = BoxLayout(
            size_hint_y=None,
            height=dp(48),
            spacing=dp(8)
        )

        popup = Popup(
            title="Save File",
            content=root,
            size_hint=(0.9, 0.8)
        )

        def save_selected(*args):

            name = name_input.text.strip()

            if not name:
                return

            if not name.lower().endswith(
                DEFAULT_EXTENSION
            ):
                name += DEFAULT_EXTENSION

            folder = (
                chooser.path
                if chooser.path
                else os.path.expanduser("~")
            )

            path = os.path.join(
                folder,
                name
            )

            try:

                with open(
                    path,
                    "wb"
                ) as f:

                    f.write(
                        encrypt_to_bytes(
                            data,
                            password
                        )
                    )

                popup.dismiss()

                callback(
                    path
                )

            except Exception as e:

                popup.dismiss()

                callback(
                    None,
                    str(e)
                )

        buttons.add_widget(
            make_button(
                "Cancel",
                lambda x: popup.dismiss(),
                RED
            )
        )

        buttons.add_widget(
            make_button(
                "Save",
                save_selected,
                GREEN
            )
        )

        root.add_widget(
            buttons
        )

        popup.open()


# ============================================================
# START SCREEN
# ============================================================

class StartScreen(Screen):

    def __init__(self, **kwargs):

        super().__init__(**kwargs)

        root = BoxLayout(
            orientation="vertical",
            padding=dp(30),
            spacing=dp(20)
        )

        root.add_widget(
            Widget()
        )

        title = make_label(
            "🔐 Secure Password Manager",
            22,
            WHITE,
            True,
            halign="center"
        )

        root.add_widget(
            title
        )

        subtitle = make_label(
            "Welcome! Choose an option:",
            14,
            GRAY,
            halign="center"
        )

        root.add_widget(
            subtitle
        )

        root.add_widget(
            Widget(
                size_hint_y=None,
                height=dp(20)
            )
        )

        root.add_widget(
            make_button(
                "📂 Import File",
                self.import_file,
                BLUE,
                dp(55)
            )
        )

        root.add_widget(
            make_button(
                "➕ Create New File",
                self.create_file,
                GREEN,
                dp(55)
            )
        )

        root.add_widget(
            Widget()
        )

        self.add_widget(
            root
        )

    def import_file(self, *args):

        App.get_running_app().prompt_open_file()

    def create_file(self, *args):

        App.get_running_app().manager.current = "create"


# ============================================================
# CREATE SCREEN
# ============================================================

class CreateScreen(Screen):

    def __init__(self, **kwargs):

        super().__init__(**kwargs)

        root = BoxLayout(
            orientation="vertical",
            padding=dp(25),
            spacing=dp(10)
        )

        root.add_widget(
            Widget()
        )

        title = make_label(
            "➕ Create New File",
            22,
            WHITE,
            True,
            halign="center"
        )

        root.add_widget(
            title
        )

        root.add_widget(
            make_label(
                "File Name",
                13,
                GRAY
            )
        )

        self.filename = make_input(
            hint="e.g. MyPasswords"
        )

        root.add_widget(
            self.filename
        )

        root.add_widget(
            make_label(
                "Password",
                13,
                GRAY
            )
        )

        self.password = make_input(
            password=True,
            hint="Minimum 8 characters"
        )

        root.add_widget(
            self.password
        )

        root.add_widget(
            make_label(
                "Confirm Password",
                13,
                GRAY
            )
        )

        self.confirm = make_input(
            password=True,
            hint="Type password again"
        )

        root.add_widget(
            self.confirm
        )

        root.add_widget(
            Widget(
                size_hint_y=None,
                height=dp(10)
            )
        )

        root.add_widget(
            make_button(
                "Create",
                self.submit,
                GREEN,
                dp(50)
            )
        )

        root.add_widget(
            make_button(
                "Back",
                lambda x:
                setattr(
                    App.get_running_app().manager,
                    "current",
                    "start"
                ),
                RED,
                dp(50)
            )
        )

        root.add_widget(
            Widget()
        )

        self.add_widget(
            root
        )

    def on_enter(self, *args):

        self.filename.text = ""
        self.password.text = ""
        self.confirm.text = ""

    def submit(self, *args):

        name = self.filename.text.strip()
        pwd = self.password.text

        if not name:

            return App.get_running_app().show_message(
                "Error",
                "Filename required."
            )

        if len(pwd) < 8:

            return App.get_running_app().show_message(
                "Error",
                "Password must be at least 8 characters."
            )

        if pwd != self.confirm.text:

            return App.get_running_app().show_message(
                "Error",
                "Passwords do not match."
            )

        App.get_running_app().create_new_file(
            name,
            pwd
        )


# ============================================================
# ACCOUNT CARD
# ============================================================

class AccountCard(BoxLayout):

    def __init__(
        self,
        index,
        account,
        delete_callback,
        change_callback,
        **kwargs
    ):

        super().__init__(
            orientation="vertical",
            spacing=dp(8),
            padding=dp(14),
            size_hint_y=None,
            **kwargs
        )

        self.index = index
        self.account = account
        self.delete_callback = delete_callback
        self.change_callback = change_callback

        self.is_loading = True

        self.height = dp(290)

        with self.canvas.before:

            Color(*CARD_COLOR)

            self.bg = RoundedRectangle(
                pos=self.pos,
                size=self.size,
                radius=[dp(14)]
            )

        self.bind(
            pos=self.update_bg,
            size=self.update_bg
        )

        self.title = make_label(
            account.get("type") or "Account",
            18,
            WHITE,
            True
        )

        self.add_widget(
            self.title
        )

        # Type
        self.type_input = make_input(
            account.get("type", ""),
            hint="Account Type (e.g. Gmail)"
        )

        self.add_labeled(
            "Type",
            self.type_input
        )

        # Email / Username
        self.email_input = make_input(
            account.get("email", ""),
            hint="Email or Username"
        )

        self.add_labeled(
            "Email / User",
            self.email_input
        )

        # Password row
        pass_row = BoxLayout(
            orientation="horizontal",
            spacing=dp(6),
            size_hint_y=None,
            height=dp(48)
        )

        self.pass_input = make_input(
            account.get("pass", ""),
            password=True,
            hint="Password"
        )

        pass_row.add_widget(
            self.pass_input
        )

        eye_btn = Button(
            text="👁",
            size_hint_x=None,
            width=dp(52),
            background_normal="",
            background_color=BLUE,
            font_size=sp(17)
        )

        eye_btn.bind(
            on_release=lambda x:
            setattr(
                self.pass_input,
                "password",
                not self.pass_input.password
            )
        )

        pass_row.add_widget(
            eye_btn
        )

        self.add_labeled(
            "Password",
            pass_row
        )

        self.add_widget(
            make_button(
                "🗑 Delete",
                self.delete_clicked,
                RED,
                dp(44)
            )
        )

        self.type_input.bind(
            text=self.on_val_change
        )

        self.email_input.bind(
            text=self.on_val_change
        )

        self.pass_input.bind(
            text=self.on_val_change
        )

        self.is_loading = False

    def add_labeled(
        self,
        label_text,
        widget
    ):

        lbl = make_label(
            label_text,
            12,
            GRAY,
            False
        )

        lbl.height = dp(20)

        self.add_widget(
            lbl
        )

        self.add_widget(
            widget
        )

    def update_bg(self, *args):

        self.bg.pos = self.pos
        self.bg.size = self.size

    def on_val_change(
        self,
        instance,
        value
    ):

        if self.is_loading:
            return

        self.account["type"] = (
            self.type_input.text
        )

        self.account["email"] = (
            self.email_input.text
        )

        self.account["pass"] = (
            self.pass_input.text
        )

        self.title.text = (
            self.type_input.text
            if self.type_input.text
            else "Account"
        )

        self.change_callback()

    def delete_clicked(self, *args):

        self.delete_callback(
            self.index
        )


# ============================================================
# MAIN SCREEN
# ============================================================

class MainScreen(Screen):

    def __init__(self, **kwargs):

        super().__init__(**kwargs)

        self.cards = []

        self.build()

    def build(self):

        root = BoxLayout(
            orientation="vertical"
        )

        top = BoxLayout(
            orientation="horizontal",
            padding=[dp(10), dp(8)],
            spacing=dp(6),
            size_hint_y=None,
            height=dp(62)
        )

        title = make_label(
            "🔑 Vault",
            18,
            WHITE,
            True
        )

        title.size_hint_x = 1

        top.add_widget(
            title
        )

        self.btn_save = make_button(
            "💾",
            self.action_save,
            DISABLED,
            dp(45)
        )

        self.btn_save.size_hint_x = None
        self.btn_save.width = dp(45)
        self.btn_save.disabled = True

        App.get_running_app().bind(
            has_unsaved_changes=self.update_save_btn
        )

        top.add_widget(
            self.btn_save
        )

        btn_add = make_button(
            "➕",
            self.action_add,
            GREEN,
            dp(45)
        )

        btn_add.size_hint_x = None
        btn_add.width = dp(45)

        top.add_widget(
            btn_add
        )

        btn_import = make_button(
            "📥",
            self.action_import_append,
            BLUE,
            dp(45)
        )

        btn_import.size_hint_x = None
        btn_import.width = dp(45)

        top.add_widget(
            btn_import
        )

        btn_export = make_button(
            "📤",
            self.action_export,
            BLUE,
            dp(45)
        )

        btn_export.size_hint_x = None
        btn_export.width = dp(45)

        top.add_widget(
            btn_export
        )

        btn_exit = make_button(
            "🚪",
            self.action_exit,
            RED,
            dp(45)
        )

        btn_exit.size_hint_x = None
        btn_exit.width = dp(45)

        top.add_widget(
            btn_exit
        )

        root.add_widget(
            top
        )

        self.scroll = ScrollView(
            do_scroll_x=False,
            do_scroll_y=True
        )

        self.container = GridLayout(
            cols=1,
            spacing=dp(12),
            padding=[dp(10), dp(10)],
            size_hint_y=None
        )

        self.container.bind(
            minimum_height=self.container.setter(
                "height"
            )
        )

        self.scroll.add_widget(
            self.container
        )

        root.add_widget(
            self.scroll
        )

        self.add_widget(
            root
        )

    def update_save_btn(
        self,
        instance,
        value
    ):

        self.btn_save.disabled = not value

        self.btn_save.background_color = (
            BLUE if value else DISABLED
        )

    def refresh(self):

        self.container.clear_widgets()
        self.cards.clear()

        app = App.get_running_app()

        if not app.data:

            empty = make_label(
                "No accounts yet.\n\nPress ➕ to add one.",
                15,
                GRAY,
                halign="center"
            )

            self.container.add_widget(
                empty
            )

            return

        for index, acc in enumerate(app.data):

            card = AccountCard(
                index,
                acc,
                self.delete_account,
                self.mark_changed
            )

            self.cards.append(
                card
            )

            self.container.add_widget(
                card
            )

    def mark_changed(self):

        App.get_running_app().has_unsaved_changes = True

    def action_add(self, *args):

        app = App.get_running_app()

        app.data.insert(
            0,
            {
                "type": "",
                "email": "",
                "pass": ""
            }
        )

        app.has_unsaved_changes = True

        self.refresh()

    def delete_account(
        self,
        index
    ):

        app = App.get_running_app()

        if 0 <= index < len(app.data):

            del app.data[index]

            app.has_unsaved_changes = True

            self.refresh()

    def action_save(self, *args):

        app = App.get_running_app()

        if not app.current_filepath:

            app.show_message(
                "Save Error",
                "No vault file is currently open."
            )

            return

        success = app.file_manager.write_to_uri(
            app.current_filepath,
            app.data,
            app.current_password
        )

        if success:

            app.has_unsaved_changes = False

            app.show_message(
                "Saved",
                "All changes have been safely saved!"
            )

        else:

            app.show_message(
                "Save Error",
                "Could not write file. "
                "Check write permissions."
            )

    def action_import_append(self, *args):

        App.get_running_app().prompt_open_file(
            append=True
        )

    def action_export(self, *args):

        root = BoxLayout(
            orientation="vertical",
            padding=dp(15),
            spacing=dp(12)
        )

        root.add_widget(
            make_label(
                "Export Options:",
                16,
                WHITE
            )
        )

        popup = Popup(
            title="Export File",
            content=root,
            size_hint=(0.85, None),
            height=dp(250)
        )

        def do_share(*args):

            popup.dismiss()

            app = App.get_running_app()

            app.file_manager.share_file(
                app.data,
                app.current_password
            )

        def do_save_local(*args):

            popup.dismiss()

            app = App.get_running_app()

            app.file_manager.create_file(
                "Exported_Vault.enc",
                app.data,
                app.current_password,
                lambda uri, error=None:
                app.show_message(
                    "Exported",
                    "Saved successfully!"
                )
                if uri
                else app.show_message(
                    "Export Error",
                    error or "Could not save file."
                )
            )

        root.add_widget(
            make_button(
                "📤 Share File",
                do_share,
                BLUE
            )
        )

        root.add_widget(
            make_button(
                "💾 Save Local Copy",
                do_save_local,
                GREEN
            )
        )

        root.add_widget(
            make_button(
                "Cancel",
                lambda x: popup.dismiss(),
                RED
            )
        )

        popup.open()

    def action_exit(self, *args):

        app = App.get_running_app()

        if app.has_unsaved_changes:

            root = BoxLayout(
                orientation="vertical",
                padding=dp(15),
                spacing=dp(12)
            )

            root.add_widget(
                make_label(
                    "You have unsaved changes!\n"
                    "Exit without saving?",
                    15,
                    WHITE,
                    halign="center"
                )
            )

            popup = Popup(
                title="Warning",
                content=root,
                size_hint=(0.85, None),
                height=dp(200)
            )

            buttons = BoxLayout(
                spacing=dp(10),
                size_hint_y=None,
                height=dp(48)
            )

            buttons.add_widget(
                make_button(
                    "Cancel",
                    lambda x: popup.dismiss(),
                    BLUE
                )
            )

            buttons.add_widget(
                make_button(
                    "Exit Anyway",
                    lambda x: app.stop(),
                    RED
                )
            )

            root.add_widget(
                buttons
            )

            popup.open()

        else:

            app.stop()


# ============================================================
# MAIN APPLICATION
# ============================================================

class PasswordManagerApp(App):

    has_unsaved_changes = BooleanProperty(False)

    def build(self):

        self.title = "Secure Vault"

        Window.clearcolor = BG_COLOR

        self.current_filepath = None
        self.current_password = None
        self.data = []

        self.file_manager = NativeFileManager(
            self
        )

        self.manager = ScreenManager()

        self.manager.add_widget(
            StartScreen(
                name="start"
            )
        )

        self.manager.add_widget(
            CreateScreen(
                name="create"
            )
        )

        self.main_screen = MainScreen(
            name="main"
        )

        self.manager.add_widget(
            self.main_screen
        )

        return self.manager

    # --------------------------------------------------------
    # MESSAGE POPUP
    # --------------------------------------------------------

    def show_message(
        self,
        title,
        message
    ):

        popup = Popup(
            title=title,
            content=make_label(
                message,
                14,
                halign="center"
            ),
            size_hint=(0.85, None),
            height=dp(200)
        )

        popup.open()

    # --------------------------------------------------------
    # PASSWORD PROMPT
    # --------------------------------------------------------

    def prompt_password(
        self,
        callback
    ):

        root = BoxLayout(
            orientation="vertical",
            padding=dp(15),
            spacing=dp(12)
        )

        root.add_widget(
            make_label(
                "Enter File Password:",
                14,
                GRAY
            )
        )

        pwd_input = make_input(
            password=True,
            hint="Password"
        )

        root.add_widget(
            pwd_input
        )

        popup = Popup(
            title="Unlock",
            content=root,
            size_hint=(0.85, None),
            height=dp(220),
            auto_dismiss=False
        )

        buttons = BoxLayout(
            spacing=dp(8),
            size_hint_y=None,
            height=dp(48)
        )

        def submit(*args):

            val = pwd_input.text

            if not val:
                return

            popup.dismiss()

            callback(
                val
            )

        buttons.add_widget(
            make_button(
                "Cancel",
                lambda x: popup.dismiss(),
                RED
            )
        )

        buttons.add_widget(
            make_button(
                "Unlock",
                submit,
                GREEN
            )
        )

        root.add_widget(
            buttons
        )

        popup.open()

    # --------------------------------------------------------
    # OPEN / IMPORT FILE
    # --------------------------------------------------------

    def prompt_open_file(
        self,
        append=False
    ):

        def on_file_picked(
            raw,
            uri=None,
            error=None
        ):

            if error:

                self.show_message(
                    "Error",
                    error
                )

                return

            if not raw:

                return

            def on_password_entered(
                pwd
            ):

                try:

                    decrypted = decrypt_from_bytes(
                        raw,
                        pwd
                    )

                    if append:

                        self.data.extend(
                            decrypted
                        )

                        self.has_unsaved_changes = True

                        self.main_screen.refresh()

                        self.show_message(
                            "Success",
                            "Data imported successfully!"
                        )

                    else:

                        self.current_password = pwd

                        self.current_filepath = uri

                        self.data = decrypted

                        self.has_unsaved_changes = False

                        self.main_screen.refresh()

                        self.manager.current = "main"

                except Exception:

                    self.show_message(
                        "Decryption Error",
                        "Wrong password or corrupted file."
                    )

            self.prompt_password(
                on_password_entered
            )

        self.file_manager.open_file(
            on_file_picked
        )

    # --------------------------------------------------------
    # CREATE NEW VAULT FILE
    # --------------------------------------------------------

    def create_new_file(
        self,
        filename,
        password
    ):

        def on_created(
            uri,
            error=None
        ):

            if error:

                self.show_message(
                    "Error",
                    error
                )

                return

            if not uri:

                return

            self.current_password = password

            self.current_filepath = uri

            self.data = []

            self.has_unsaved_changes = False

            self.main_screen.refresh()

            self.manager.current = "main"

        self.file_manager.create_file(
            filename,
            [],
            password,
            on_created
        )

# ============================================================
# APP START
# ============================================================

if __name__ == "__main__":

    PasswordManagerApp().run()