import json
import os
import time
import random
import webbrowser
import gc
import sys
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image, ImageTk
from gostcrypto import gosthash, gostcipher, gostsignature
import qrcode

# ====================== КОНСТАНТЫ ======================
DEVICE_ID = "TERMINAL_2026_001"
SOFTWARE_VERSION = "2.8"
KEYS_FILE = "secure_keys.json"
LOG_FILE = "secure_audit.log"
RECEIPTS_DIR = "receipts"
CONFIG_FILE = "config.json"
TRANSACTIONS_FILE = "transactions.json"
INTEGRITY_MANIFEST = "integrity_manifest.json"

os.makedirs(RECEIPTS_DIR, exist_ok=True)


# ====================== КРИПТОГРАФИЧЕСКИЕ ФУНКЦИИ ======================
def gost_hash(data: str | bytes, size: str = "512") -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    hash_obj = gosthash.new(f'streebog{size}')
    hash_obj.update(data)
    return hash_obj.hexdigest()


def kuznechik_encrypt(plaintext: str | bytes) -> str:
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    pad_len = (32 - len(plaintext) % 32) % 32
    plaintext += b'\0' * pad_len
    cipher_obj = gostcipher.new('kuznechik', KUZNECHIK_KEY, gostcipher.MODE_ECB, pad_mode=gostcipher.PAD_MODE_1)
    ct = cipher_obj.encrypt(plaintext)
    return ct.hex() + "_KUZ"


def kuznechik_decrypt(ciphertext: str) -> str:
    if not ciphertext.endswith("_KUZ"):
        return ciphertext
    ct_hex = ciphertext.replace("_KUZ", "")
    ct_bytes = bytes.fromhex(ct_hex)
    cipher_obj = gostcipher.new('kuznechik', KUZNECHIK_KEY, gostcipher.MODE_ECB, pad_mode=gostcipher.PAD_MODE_1)
    pt = cipher_obj.decrypt(ct_bytes)
    return pt.rstrip(b'\0').decode("utf-8", errors="ignore")


def generate_eds(data: str | dict) -> str:
    if isinstance(data, dict):
        data = json.dumps(data, ensure_ascii=False, sort_keys=True)
    hash_obj = gosthash.new('streebog256')
    hash_obj.update(data.encode("utf-8"))
    digest = hash_obj.digest()
    sign_obj = gostsignature.new(
        gostsignature.MODE_256,
        gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB']
    )
    signature = sign_obj.sign(PRIVATE_KEY, digest)
    return signature.hex()


def verify_eds(data: str | dict, signature_hex: str) -> bool:
    if isinstance(data, dict):
        data = json.dumps(data, ensure_ascii=False, sort_keys=True)
    hash_obj = gosthash.new('streebog256')
    hash_obj.update(data.encode("utf-8"))
    digest = hash_obj.digest()
    try:
        signature = bytes.fromhex(signature_hex)
    except:
        return False
    sign_obj = gostsignature.new(
        gostsignature.MODE_256,
        gostsignature.CURVES_R_1323565_1_024_2019['id-tc26-gost-3410-2012-256-paramSetB']
    )
    return sign_obj.verify(PUBLIC_KEY, digest, signature)


# ====================== ЗАЩИЩЁННЫЙ ЖУРНАЛ ======================
def log_event(event_type: str, details: dict):
    timestamp = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    entry = {
        "timestamp": timestamp,
        "device_id": DEVICE_ID,
        "version": SOFTWARE_VERSION,
        "event_type": event_type,
        "details": details,
        "hash": gost_hash(json.dumps(details, ensure_ascii=False))
    }
    signature = generate_eds(entry)
    entry["eds_signature"] = signature

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    print(f"🔒 [SECURE LOG] {event_type}")


# ====================== КОНТРОЛЬ ЦЕЛОСТНОСТИ ======================
def generate_integrity_manifest():
    critical_files = [CONFIG_FILE, TRANSACTIONS_FILE, KEYS_FILE, LOG_FILE]
    manifest = {"files": {}}

    for filepath in critical_files:
        if os.path.exists(filepath):
            with open(filepath, "rb") as f:
                data = f.read()
            manifest["files"][filepath] = gost_hash(data)
        else:
            manifest["files"][filepath] = None

    manifest_json = json.dumps(manifest["files"], ensure_ascii=False, sort_keys=True)
    manifest["eds_signature"] = generate_eds(manifest_json)
    manifest["timestamp"] = datetime.now().strftime("%d.%m.%Y %H:%M:%S")

    with open(INTEGRITY_MANIFEST, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    print("🔐 Манифест целостности успешно создан/обновлён")


def verify_integrity() -> bool:
    if not os.path.exists(INTEGRITY_MANIFEST):
        log_event("INTEGRITY_FAIL", {"reason": "manifest_missing"})
        return False

    try:
        with open(INTEGRITY_MANIFEST, "r", encoding="utf-8") as f:
            manifest = json.load(f)

        critical_files = [CONFIG_FILE, TRANSACTIONS_FILE, KEYS_FILE]
        for filepath in critical_files:
            expected_hash = manifest["files"].get(filepath)
            if expected_hash is None:
                continue

            if os.path.exists(filepath):
                with open(filepath, "rb") as f:
                    current_hash = gost_hash(f.read())
                if current_hash != expected_hash:
                    log_event("INTEGRITY_FAIL", {"file": filepath, "reason": "hash_mismatch"})
                    return False
            else:
                log_event("INTEGRITY_FAIL", {"file": filepath, "reason": "file_missing"})
                return False

        log_event("INTEGRITY_CHECK", {"status": "ALL_FILES_OK"})
        print("✅ Целостность проверена")
        return True

    except Exception as e:
        log_event("INTEGRITY_FAIL", {"reason": "exception", "error": str(e)})
        return False

def check_integrity():
    if not verify_integrity():
        messagebox.showerror(
            "КРИТИЧЕСКАЯ ОШИБКА ЦЕЛОСТНОСТИ",
            "Обнаружено нарушение целостности файлов!\n\n"
            "Программа остановлена для предотвращения мошенничества.\n"
            "Обратитесь к администратору системы."
        )
        log_event("SYSTEM_SHUTDOWN", {"reason": "integrity_violation"})
        sys.exit(1)
    return True


# ====================== БЕЗОПАСНОЕ УПРАВЛЕНИЕ КЛЮЧАМИ ======================
def generate_secure_key(length: int = 32) -> bytes:
    return os.urandom(length)


def load_or_create_keys():
    if os.path.exists(KEYS_FILE):
        try:
            with open(KEYS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            print("🔑 Ключи загружены из secure_keys.json")
            return (bytes.fromhex(data["kuznechik_key"]),
                    bytes.fromhex(data["private_key"]),
                    bytes.fromhex(data["public_key"]))
        except Exception:
            pass

    kuznechik_key = generate_secure_key(32)
    private_key = generate_secure_key(32)
    public_key = generate_secure_key(64)

    data = {
        "kuznechik_key": kuznechik_key.hex(),
        "private_key": private_key.hex(),
        "public_key": public_key.hex()
    }
    with open(KEYS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)

    print("🔑 Сгенерированы новые криптографические ключи")
    return kuznechik_key, private_key, public_key


KUZNECHIK_KEY, PRIVATE_KEY, PUBLIC_KEY = load_or_create_keys()

# ====================== ЗАЩИТА ДАННЫХ КАРТ ======================
def protect_card_data(card: dict) -> dict:
    protected = card.copy()
    protected["number"] = kuznechik_encrypt(protected["number"])
    protected["cvv"] = kuznechik_encrypt(protected["cvv"])
    protected["pin"] = kuznechik_encrypt(protected["pin"])
    protected["token"] = f"TOKEN_{kuznechik_decrypt(protected['number'])[-4:]}"
    log_event("CARD_ENCRYPTED", {"last4": kuznechik_decrypt(protected["number"])[-4:]})
    return protected


def unprotect_card_data(protected: dict) -> dict:
    card = protected.copy()
    card["number"] = kuznechik_decrypt(card["number"])
    card["cvv"] = kuznechik_decrypt(card["cvv"])
    card["pin"] = kuznechik_decrypt(card["pin"])
    return card


# ====================== ПОМОЩНИКИ ======================
def create_card(number: str, expiry: str, cvv: str, pin: str = "1234"):
    number = number.replace(" ", "")
    card = {"number": number, "expiry": expiry, "cvv": cvv, "pin": pin}
    return protect_card_data(card)


def create_transaction(amount: float, card_number: str, status: str, method: str, recipient: str, recipient_type: str):
    return {
        "timestamp": datetime.now().strftime("%d.%m.%Y %H:%M:%S"),
        "amount": round(amount, 2),
        "card_last4": card_number[-4:],
        "status": status,
        "method": method,
        "recipient": recipient,
        "recipient_type": recipient_type
    }


def transaction_save_history(transactions_list):
    protected = []
    for t in transactions_list:
        pt = t.copy()
        if "card_number" in pt:
            pt["card_number"] = kuznechik_encrypt(pt["card_number"])
        protected.append(pt)
    data_json = json.dumps(protected, ensure_ascii=False)
    protected_data = {
        "data": protected,
        "hash": gost_hash(data_json),
        "eds_signature": generate_eds(data_json)
    }
    with open(TRANSACTIONS_FILE, "w", encoding="utf-8") as f:
        json.dump(protected_data, f, ensure_ascii=False, indent=2)
    generate_integrity_manifest()


def load_transactions():
    global transactions
    if os.path.exists(TRANSACTIONS_FILE):
        try:
            with open(TRANSACTIONS_FILE, "r", encoding="utf-8") as f:
                protected = json.load(f)
            if verify_eds(protected["data"], protected["eds_signature"]):
                transactions = protected["data"]
                for t in transactions:
                    if "card_number" in t and isinstance(t["card_number"], str):
                        t["card_number"] = kuznechik_decrypt(t["card_number"])
            else:
                log_event("INTEGRITY_FAIL", {"file": TRANSACTIONS_FILE})
                transactions = []
        except Exception:
            transactions = []
    else:
        transactions = []


def hash_password(password: str) -> str:
    return gost_hash(password)


def load_password_hash():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("admin_password_hash")
    except:
        default_hash = hash_password("admin123")
        save_password_hash(default_hash)
        return default_hash


def save_password_hash(password_hash: str):
    data = {"admin_password_hash": password_hash}
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    generate_integrity_manifest()


# ====================== ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ======================
transactions = []
admin_password_hash = None
current_recipient = None
current_recipient_type = None
role = "operator"
failed_attempts = 0
admin_failed_attempts = 0
admin_lock_time = 0
token_failed_attempts = 0
token_lock_time = 0
change_pass_failed_attempts = 0
change_pass_lock_time = 0
root = None
amount_entry = None
recipient_label = None
history_text = None
nfc_btn = None


# ====================== ЦЕНТРИРОВАНИЕ ОКОН ======================
def center_window(win):
    win.update_idletasks()
    width = win.winfo_width()
    height = win.winfo_height()
    x = (win.winfo_screenwidth() // 2) - (width // 2)
    y = (win.winfo_screenheight() // 2) - (height // 2)
    win.geometry(f"+{x}+{y}")


# ====================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ======================

def ask_string_with_icon(title: str, prompt: str, show: str = None, parent=None):
    if parent is None:
        parent = root
    win = tk.Toplevel(parent)
    win.title(title)
    win.geometry("420x220")
    win.configure(bg="#0a1f0a")
    win.grab_set()
    win.iconbitmap("sources\\icon.ico")
    center_window(win)

    tk.Label(win, text=prompt, font=("Arial", 12, "bold"),
             bg="#0a1f0a", fg="#00ff88", wraplength=380).pack(pady=20)

    entry = tk.Entry(win, font=("Arial", 14), show=show, width=30, justify="center")
    entry.pack(pady=10)
    entry.focus_set()

    result = [None]

    def confirm():
        result[0] = entry.get()
        win.destroy()

    def cancel():
        result[0] = None
        win.destroy()

    btn_frame = tk.Frame(win, bg="#0a1f0a")
    btn_frame.pack(pady=20)
    ttk.Button(btn_frame, text="✅ OK", command=confirm).pack(side="left", padx=30)
    ttk.Button(btn_frame, text="❌ Отмена", command=cancel).pack(side="right", padx=30)

    win.bind("<Return>", lambda e: confirm())
    win.bind("<Escape>", lambda e: cancel())

    win.wait_window(win)
    return result[0]

def mask_recipient(recipient: str, rec_type: str) -> str:
    if rec_type == "Телефон" and recipient.startswith("+7") and len(recipient) == 12:
        return recipient[:2] + "******" + recipient[-4:]
    elif rec_type == "Карта" and len(recipient) == 16:
        return "**** **** **** " + recipient[-4:]
    return recipient[:8] + "..." if len(recipient) > 8 else recipient


def validate_minimum_amount():
    try:
        amount = float(amount_entry.get())
        if amount < 10.00:
            messagebox.showerror("Ошибка", "Минимальная сумма платежа — 10.00 ₽")
            return False
        return True
    except:
        messagebox.showerror("Ошибка", "Введите корректную сумму!")
        return False


def validate_amount_input(P):
    if P == "":
        return True
    if P.count(".") > 1:
        return False
    if not all(c.isdigit() or c == "." for c in P):
        return False
    if "." in P:
        decimal = P.split(".")[1]
        if len(decimal) > 2:
            return False
    if len(P) > 12:
        return False
    return True


def create_widgets():
    global amount_entry, recipient_label, history_text, nfc_btn

    tk.Label(root, text="ПЛАТЁЖНЫЙ ТЕРМИНАЛ", font=("Arial", 24, "bold"),
             bg="#0a1f0a", fg="#00ff88").pack(pady=20)

    screen_frame = tk.LabelFrame(root, text="ДИСПЛЕЙ ТЕРМИНАЛА", font=("Arial", 10),
                                 bg="#112211", fg="#00ff88", labelanchor="n")
    screen_frame.pack(pady=10, padx=40, fill="x")

    tk.Label(screen_frame, text="Сумма к оплате:", font=("Arial", 14), bg="#112211", fg="#ffffff").pack(pady=(15, 5))

    amount_entry = tk.Entry(screen_frame, font=("Arial", 26, "bold"), justify="center",
                            bg="#223322", fg="#00ff88", insertbackground="#00ff88", width=12)
    amount_entry.insert(0, "0.00")
    vcmd = root.register(validate_amount_input)
    amount_entry.config(validate="key", validatecommand=(vcmd, '%P'))
    amount_entry.pack(pady=8)

    tk.Label(screen_frame, text="Выберите способ отправки денег:", font=("Arial", 12),
             bg="#112211", fg="#ffff00").pack(pady=(20, 8))

    ttk.Button(screen_frame, text="📱 Отправка по номеру телефона",
               width=35, command=ask_phone_recipient).pack(pady=6)
    ttk.Button(screen_frame, text="💳 Отправка по реквизитам карты",
               width=35, command=ask_card_recipient).pack(pady=6)

    recipient_label = tk.Label(screen_frame, text="Получатель: Не указан", font=("Arial", 11),
                               bg="#112211", fg="#ffff00", wraplength=500)
    recipient_label.pack(pady=15)

    btn_frame = tk.Frame(root, bg="#0a1f0a")
    btn_frame.pack(pady=25)

    ttk.Button(btn_frame, text="💳 Вставить карту", width=28, command=insert_card).pack(pady=8)
    nfc_btn = ttk.Button(btn_frame, text="📱 Приложить телефон (NFC)", width=28, command=nfc_tap)
    nfc_btn.pack(pady=8)
    ttk.Button(btn_frame, text="🔲 Сканировать QR-код", width=28, command=qr_scan).pack(pady=8)

    ttk.Button(root, text="Панель администратора", command=open_admin_panel).pack(pady=15)

    tk.Label(root, text="Последние транзакции", font=("Arial", 12), bg="#0a1f0a", fg="#00ff88").pack(pady=(10, 5))
    history_text = tk.Text(root, height=12, width=82, bg="#112211", fg="#00ff88",
                           font=("Consolas", 10), relief="flat", bd=3)
    history_text.pack(pady=5, padx=30)

    ttk.Button(root, text="Очистить историю", command=clear_history).pack(pady=10)

    update_history()


# ====================== ОКНА ВВОДА И ОСНОВНАЯ ЛОГИКА ======================
def ask_phone_recipient():
    global current_recipient, current_recipient_type, recipient_label
    win = tk.Toplevel(root)
    win.title("Отправка по номеру телефона")
    win.geometry("460x280")
    win.configure(bg="#0a1f0a")
    win.grab_set()
    win.iconbitmap("sources\\icon.ico")
    center_window(win)

    tk.Label(win, text="Введите номер телефона получателя", font=("Arial", 12, "bold"),
             bg="#0a1f0a", fg="#00ff88").pack(pady=15)

    entry = tk.Entry(win, font=("Arial", 18), justify="center", width=20)
    entry.insert(0, "+7")
    entry.icursor(2)
    entry.pack(pady=10)

    def validate(P):
        if len(P) < 2 or not P.startswith("+7"):
            return False
        if len(P) > 12:
            return False
        return P[2:].isdigit() if len(P) > 2 else True

    vcmd = win.register(validate)
    entry.config(validate="key", validatecommand=(vcmd, '%P'))

    def confirm():
        global current_recipient, current_recipient_type, recipient_label
        value = entry.get().strip()
        if not value.startswith("+7") or len(value) != 12 or not value[2:].isdigit():
            messagebox.showerror("Ошибка", "Номер должен быть +7XXXXXXXXXX", parent=win)
            return
        if messagebox.askyesno("Подтверждение", f"Сумма: {amount_entry.get()} ₽\nТелефон: {value}\n\nВсё верно?", parent=win):
            current_recipient = value
            current_recipient_type = "Телефон"
            recipient_label.config(text=f"Получатель: Телефон → {value}")
            win.destroy()

    ttk.Button(win, text="✅ Подтвердить", command=confirm).pack(pady=20)


def ask_card_recipient():
    global current_recipient, current_recipient_type, recipient_label
    win = tk.Toplevel(root)
    win.title("Отправка по реквизитам карты")
    win.geometry("460x280")
    win.configure(bg="#0a1f0a")
    win.grab_set()
    win.iconbitmap("sources\\icon.ico")
    center_window(win)

    tk.Label(win, text="Введите номер карты получателя", font=("Arial", 12, "bold"),
             bg="#0a1f0a", fg="#00ff88").pack(pady=15)

    entry = tk.Entry(win, font=("Arial", 18), justify="center", width=25)
    entry.pack(pady=10)

    def validate(P):
        if len(P) > 16:
            return False
        return P.isdigit() or P == ""

    vcmd = win.register(validate)
    entry.config(validate="key", validatecommand=(vcmd, '%P'))

    def confirm():
        global current_recipient, current_recipient_type, recipient_label
        value = entry.get().strip()
        if len(value) != 16 or not value.isdigit():
            messagebox.showerror("Ошибка", "Номер карты — ровно 16 цифр", parent=win)
            return
        if messagebox.askyesno("Подтверждение",
                               f"Сумма: {amount_entry.get()} ₽\nКарта: {value[:4]} **** **** {value[-4:]}\n\nВсё верно?",
                               parent=win):
            current_recipient = value
            current_recipient_type = "Карта"
            recipient_label.config(text=f"Получатель: Карта → {value[:4]} **** **** {value[-4:]}")
            win.destroy()

    ttk.Button(win, text="✅ Подтвердить", command=confirm).pack(pady=20)


def show_qr_window(data: str):
    win = tk.Toplevel(root)
    win.title("QR-код для сканирования")
    win.geometry("600x600")
    win.configure(bg="#0a1f0a")
    win.grab_set()
    win.iconbitmap("sources\\icon.ico")
    center_window(win)

    tk.Label(win, text="Отсканируйте QR-код", font=("Arial", 14, "bold"),
             bg="#0a1f0a", fg="#00ff88").pack(pady=10)

    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#00ff88", back_color="#0a1f0a").convert('RGB')

    photo = ImageTk.PhotoImage(img)
    label = tk.Label(win, image=photo, bg="#0a1f0a")
    label.image = photo
    label.pack(pady=10)

    tk.Label(win, text="QR содержит все реквизиты платежа", font=("Arial", 10),
             bg="#0a1f0a", fg="#ffff00").pack()

    win.after(3000, win.destroy)


def qr_scan():
    global current_recipient, current_recipient_type
    if not current_recipient:
        messagebox.showwarning("Внимание", "Сначала укажите реквизиты получателя!")
        return
    if not validate_minimum_amount():
        return

    amount = amount_entry.get()
    qr_data = f"""PAYMENT
Сумма: {amount} ₽
Получатель: {current_recipient}
Тип: {current_recipient_type}
Дата: {datetime.now().strftime("%d.%m.%Y %H:%M:%S")}
Терминал: {DEVICE_ID}"""

    show_qr_window(qr_data)
    root.after(3200, lambda: simulate_payment("QR"))


def simulate_payment(method: str):
    global current_recipient, current_recipient_type, failed_attempts
    if not current_recipient:
        messagebox.showwarning("Внимание", "Сначала укажите реквизиты получателя!")
        return
    if not validate_minimum_amount():
        return

    check_integrity()
    log_event("MUTUAL_AUTH", {"method": method})
    print("✅ Взаимная аутентификация выполнена")

    number = "4276 1234 5678 9012"
    card = create_card(number, "12/28", "123", "1234")

    if method == "Карта":
        while True:
            pin_input = ask_string_with_icon("PIN-код", "Введите PIN-код карты:", show='*')
            if pin_input is None:
                log_event("CANCEL_INPUT", {"type": "pin_code"})
                clear_confidential_buffers("pin_cancel")
                return

            unprotected = unprotect_card_data(card)
            if pin_input == unprotected["pin"]:
                break

            failed_attempts += 1
            log_event("DECLINED", {"reason": "wrong_pin", "attempts": failed_attempts})
            play_beep(False)
            messagebox.showerror("Отклонено", "❌ Неверный PIN!")

            if failed_attempts >= 3:
                log_event("POSSIBLE_NSD", {"action": "brute_force_attempt"})
                clear_confidential_buffers("failed_pin")
                return

    status = "DECLINED" if random.random() < 0.50 else "APPROVED"
    play_beep(status == "APPROVED")

    add_transaction(float(amount_entry.get()), number, status, method)

    status_text = "✅ ОДОБРЕНО" if status == "APPROVED" else "❌ ОТКЛОНЕНО"
    receipt_text = f"{status_text}\nСумма: {float(amount_entry.get()):.2f} ₽\nСпособ: {method}\nПолучатель ({current_recipient_type}): {current_recipient}\nКарта: ****{number[-4:]}\nТокен: {card['token']}"

    messagebox.showinfo("Чек", receipt_text)

    if status == "APPROVED" and messagebox.askyesno("Сохранить чек", "Сохранить подписанный чек?"):
        save_signed_receipt(card, float(amount_entry.get()), method, status, receipt_text)

    clear_confidential_buffers("post_transaction")


def insert_card():
    if not current_recipient:
        messagebox.showwarning("Внимание", "Сначала укажите реквизиты получателя!")
        return
    if not validate_minimum_amount():
        return
    simulate_payment("Карта")


def nfc_tap():
    global nfc_btn
    if not current_recipient:
        messagebox.showwarning("Внимание", "Сначала укажите реквизиты получателя!")
        return
    if not validate_minimum_amount():
        return

    nfc_btn.config(text="📱 Считывание NFC...")
    root.after(1200, lambda: simulate_payment("NFC"))
    root.after(1600, lambda: nfc_btn.config(text="📱 Приложить телефон (NFC)"))


def add_transaction(amount, card_number, status, method):
    global transactions
    transaction = create_transaction(amount, card_number, status, method,
                                     current_recipient, current_recipient_type)
    transactions.append(transaction)
    transaction_save_history(transactions)
    update_history()
    log_event("TRANSACTION", {"status": status, "amount": amount, "method": method})


def update_history():
    global history_text, transactions
    history_text.delete(1.0, tk.END)
    for t in reversed(transactions[-10:]):
        masked_rec = mask_recipient(t['recipient'], t['recipient_type'])
        line = f"{t['timestamp']} | {t['amount']:8.2f} ₽ | {t['method']:6} | {t['recipient_type']:7} | {masked_rec:28} | {'✅' if t['status'] == 'APPROVED' else '❌'}\n"
        history_text.insert(tk.END, line)


def clear_history():
    global transactions
    if messagebox.askyesno("Очистка", "Очистить историю?"):
        transactions.clear()
        clear_confidential_buffers("clear_history")
        transaction_save_history([])
        update_history()


def view_logs():
    win = tk.Toplevel(root)
    win.title("Журнал событий")
    win.geometry("1280x900")
    win.configure(bg="#0a1f0a")
    win.grab_set()
    win.iconbitmap("sources\\icon.ico")
    center_window(win)

    tk.Label(win, text="Журнал защищённых событий", font=("Arial", 16, "bold"),
             bg="#0a1f0a", fg="#00ff88").pack(pady=10)

    columns = ("Дата и время", "Событие", "Детали")
    tree = ttk.Treeview(win, columns=columns, show="headings", height=35)
    tree.pack(pady=10, padx=20, fill="both", expand=True)

    for col, width in zip(columns, [190, 170, 850]):
        tree.heading(col, text=col)
        tree.column(col, width=width, anchor="w")

    scrollbar = ttk.Scrollbar(win, orient="vertical", command=tree.yview)
    scrollbar.pack(side="right", fill="y")
    tree.configure(yscrollcommand=scrollbar.set)

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        entry = json.loads(line.strip())
                        timestamp = entry.get("timestamp", "")
                        event_type = entry.get("event_type", "")
                        details_dict = entry.get("details", {})
                        details_str = " | ".join([f"{k}: {v}" for k, v in details_dict.items()]) if isinstance(details_dict, dict) else str(details_dict)
                        tree.insert("", "end", values=(timestamp, event_type, details_str))
                    except:
                        continue
    except FileNotFoundError:
        tk.Label(win, text="Файл secure_audit.log ещё не создан",
                 font=("Arial", 12), bg="#0a1f0a", fg="#ff8800").pack(pady=20)

    ttk.Button(win, text="Закрыть", command=win.destroy).pack(pady=10)


def open_admin_panel():
    global admin_failed_attempts, admin_lock_time, token_failed_attempts, token_lock_time
    now = time.time()

    if now - admin_lock_time < 60:
        remaining = int(60 - (now - admin_lock_time))
        messagebox.showerror("Блокировка", f"Слишком много неудачных попыток!\nПодождите ещё {remaining} секунд")
        return

    if now - token_lock_time < 60:
        remaining = int(60 - (now - token_lock_time))
        messagebox.showerror("Блокировка",
                             f"Слишком много неудачных попыток ввода токена!\nПодождите ещё {remaining} секунд")
        return

    token_code = ask_string_with_icon("2FA — Токен владения", "Введите код из токена:", show='*')
    if token_code is None:
        log_event("CANCEL_INPUT", {"type": "token"})
        return
    if token_code != "123456":
        token_failed_attempts += 1
        log_event("2FA_FAILED", {"reason": "wrong_token", "attempt": token_failed_attempts})
        messagebox.showerror("Ошибка", "Неверный код токена!")

        if token_failed_attempts >= 3:
            token_lock_time = time.time()
            token_failed_attempts = 0
            messagebox.showwarning("Блокировка",
                                   "Слишком много попыток ввода токена!\nОжидайте 60 секунд перед следующей попыткой")
        return

    password = ask_string_with_icon("Админ-панель", "Введите пароль администратора:", show='*')
    if password is None:
        log_event("CANCEL_INPUT", {"type": "admin_password"})
        return
    if password and hash_password(password) == admin_password_hash:
        admin_failed_attempts = 0
        change_pass_failed_attempts = 0
        log_event("ADMIN_ACCESS", {"role": "admin"})
        show_admin_window()
    else:
        admin_failed_attempts += 1
        log_event("ADMIN_FAILED", {"reason": "wrong_password", "attempt": admin_failed_attempts})
        messagebox.showerror("Ошибка", "Неверный пароль!")

        if admin_failed_attempts >= 3:
            admin_lock_time = time.time()
            admin_failed_attempts = 0
            messagebox.showwarning("Блокировка", "Слишком много попыток!\nОжидайте 60 секунд перед следующей попыткой")


def show_admin_window():
    global transactions, root
    win = tk.Toplevel(root)
    win.title("🔧 Панель администратора")
    win.geometry("1000x650")
    win.configure(bg="#0a1f0a")
    win.iconbitmap("sources\\icon.ico")
    center_window(win)

    tk.Label(win, text="Полная история + статистика", font=("Arial", 16, "bold"),
             bg="#0a1f0a", fg="#00ff88").pack(pady=10)

    approved = [t for t in transactions if t["status"] == "APPROVED"]
    total_approved = sum(t["amount"] for t in approved)
    success_rate = round(len(approved) / len(transactions) * 100, 1) if transactions else 0
    stats = f"Транзакций: {len(transactions)} | Одобрено: {len(approved)} | Сумма: {total_approved:.2f} ₽ | Успех: {success_rate}%"
    tk.Label(win, text=stats, font=("Arial", 12), bg="#0a1f0a", fg="#ffff00").pack(pady=8)

    columns = ("Дата", "Сумма", "Способ", "Тип", "Получатель", "Статус")
    tree = ttk.Treeview(win, columns=columns, show="headings", height=18)
    tree.pack(pady=10, padx=20, fill="both", expand=True)
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=130, anchor="center")

    for t in reversed(transactions):
        tree.insert("", "end", values=(
            t["timestamp"], f"{t['amount']:.2f} ₽", t["method"], t["recipient_type"],
            t["recipient"],
            "✅ ОДОБРЕНО" if t["status"] == "APPROVED" else "❌ ОТКЛОНЕНО"
        ))

    btn_frame = tk.Frame(win, bg="#0a1f0a")
    btn_frame.pack(pady=10)
    ttk.Button(btn_frame, text="Изменить пароль", command=lambda: change_password(win)).pack(side="left", padx=15)
    ttk.Button(btn_frame, text="Просмотреть логи", command=view_logs).pack(side="left", padx=15)
    ttk.Button(btn_frame, text="Закрыть", command=win.destroy).pack(side="left", padx=15)

    log_event("ADMIN_PANEL_OPEN", {"user": "admin"})


def change_password(parent_win):
    global change_pass_failed_attempts, change_pass_lock_time, admin_lock_time, admin_password_hash
    now = time.time()
    if now - change_pass_lock_time < 60:
        remaining = int(60 - (now - change_pass_lock_time))
        messagebox.showerror("Блокировка",
                             f"Слишком много неудачных попыток ввода старого пароля!\nПодождите ещё {remaining} секунд",
                             parent=parent_win)
        parent_win.destroy()
        return

    old = ask_string_with_icon("Смена пароля", "Старый пароль:", show='*', parent=parent_win)
    if old is None:
        log_event("CANCEL_CHANGE_PASSWORD", {"step": "old_password"})
        return

    if hash_password(old) != admin_password_hash:
        change_pass_failed_attempts += 1
        log_event("CHANGE_PASS_FAILED", {"reason": "wrong_old_password", "attempt": change_pass_failed_attempts})
        messagebox.showerror("Ошибка", "Неверный старый пароль", parent=parent_win)

        if change_pass_failed_attempts >= 3:
            lock_time = time.time()
            change_pass_lock_time = lock_time
            admin_lock_time = lock_time
            change_pass_failed_attempts = 0
            messagebox.showwarning("Блокировка",
                                   "Слишком много попыток ввода старого пароля!\nОжидайте 60 секунд.\nПанель администратора закрыта.",
                                   parent=parent_win)
            parent_win.destroy()
        return

    change_pass_failed_attempts = 0

    new_pass = ask_string_with_icon("Смена пароля", "Новый пароль (≥6 символов):", show='*', parent=parent_win)
    if new_pass is None:
        log_event("CANCEL_CHANGE_PASSWORD", {"step": "new_password"})
        return

    if new_pass and len(new_pass) >= 6:
        new_hash = hash_password(new_pass)
        save_password_hash(new_hash)
        admin_password_hash = new_hash
        log_event("KEY_CHANGE", {"type": "admin_password"})
        messagebox.showinfo("Успех", "Пароль изменён!", parent=parent_win)
    else:
        messagebox.showwarning("Ошибка", "Пароль слишком короткий", parent=parent_win)


def save_signed_receipt(card, amount: float, method: str, status: str, receipt_text: str):
    global transactions
    now = datetime.now()
    check_number = len(transactions)
    filename = f"receipt_{now.strftime('%d-%m-%Y_%H-%M-%S')}_{check_number:03d}.html"
    filepath = os.path.join(RECEIPTS_DIR, filename)

    eds_signature = generate_eds(receipt_text)

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Чек №{check_number}</title>
<style>body{{font-family:Arial;margin:40px;background:#f0f0f0;}}
.receipt{{max-width:420px;margin:0 auto;background:white;padding:35px;border:4px solid #00cc00;box-shadow:0 0 15px #00cc00;}}
h1{{text-align:center;color:#00cc00;}}</style></head><body>
<div class="receipt">
<h1>{"✅ ОДОБРЕНО" if status == "APPROVED" else "❌ ОТКЛОНЕНО"}</h1>
<hr>
<div><strong>Дата:</strong> {now.strftime("%d.%m.%Y %H:%M:%S")}</div>
<div><strong>Сумма:</strong> {amount:.2f} ₽</div>
<div><strong>Способ:</strong> {method}</div>
<div><strong>Получатель ({current_recipient_type}):</strong> {current_recipient}</div>
<div><strong>Карта:</strong> **** **** **** {kuznechik_decrypt(card["number"])[-4:]}</div>
<div><strong>Токен:</strong> {card["token"]}</div>
<hr>
<div style="word-break: break-all;"><strong>ЭЦП:</strong><br>{eds_signature}</div>
<p style="text-align:center; color:#006600">Подписано электронной цифровой подписью</p>
<p style="text-align:center">Эмулятор платёжного терминала v{SOFTWARE_VERSION}</p>
</div></body></html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    webbrowser.open(filepath)
    log_event("RECEIPT_SIGNED", {"check_number": check_number})
    messagebox.showinfo("Чек сохранён", f"Чек №{check_number} сохранён\nФайл: {filename}")


def play_beep(success: bool = True):
    try:
        import winsound
        freq = 1400 if success else 500
        duration = 250 if success else 600
        winsound.Beep(freq, duration)
    except ImportError:
        print('\a', end='', flush=True)


def clear_confidential_buffers(reason: str = "post_operation"):
    global current_recipient, current_recipient_type, failed_attempts
    current_recipient = None
    current_recipient_type = None
    failed_attempts = 0
    if recipient_label:
        recipient_label.config(text="Получатель: Не указан")
    gc.collect()
    log_event("BUFFER_CLEAR", {"reason": reason})
    print(f"🧹 Конфиденциальные буферы очищены ({reason})")


def init_app():
    global admin_password_hash, transactions, root
    global token_failed_attempts, token_lock_time, admin_failed_attempts, admin_lock_time
    global change_pass_failed_attempts, change_pass_lock_time

    transactions = []
    admin_password_hash = load_password_hash()
    token_failed_attempts = token_lock_time = 0
    admin_failed_attempts = admin_lock_time = 0
    change_pass_failed_attempts = change_pass_lock_time = 0

    load_transactions()

    if not os.path.exists(INTEGRITY_MANIFEST):
        generate_integrity_manifest()

    log_event("SYSTEM_START", {"action": "Запуск эмулятора с полной проверкой целостности", "role": role})

    generate_integrity_manifest()

    check_integrity()

    global_root = tk.Tk()
    global_root.iconbitmap("sources\\icon.ico")
    global_root.title("Эмулятор платёжного терминала")
    global_root.geometry("780x950")
    global_root.resizable(False, False)
    global_root.configure(bg="#0a1f0a")

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("TButton", font=("Arial", 12, "bold"), padding=10)

    global root
    root = global_root

    create_widgets()
    center_window(root)
    return global_root

def run():
    app_root = init_app()
    app_root.mainloop()


if __name__ == "__main__":
    run()