import tkinter as tk
import datetime
import string
import secrets
from tkinter import messagebox, simpledialog
from tkinter import font as tkfont
from PIL import Image, ImageTk

from src.auth.auth_manager import SESSION, logout
from src.auth.auth_manager import authenticate_user, create_user
from src.db.database import insert_entry, get_entries, delete_entry, update_entry
from src.crypto.crypto_utils import encrypt_data, decrypt_data, generate_password

# ========= THÈME (bleu sombre) =========
BG_COLOR        = "#445396"   # fond global
CARD_COLOR      = "#0F172A"   # cartes
ENTRY_BG        = "#1F2937"   # fond champs
ENTRY_FG        = "#E5E7EB"
ENTRY_PLACEHOLD = "#6B7280"

PRIMARY         = "#3B82F6"
PRIMARY_HOVER   = "#2563EB"
SECONDARY       = "#1D4ED8"
SECONDARY_HOVER = "#1E40AF"
DANGER          = "#EF4444"
DANGER_HOVER    = "#DC2626"
TEXT            = "#E5E7EB"
SUBTEXT         = "#9CA3AF"
BORDER          = "#1f2a44"

FONT        = ("Segoe UI", 12)
TITLE_FONT  = ("Segoe UI", 18, "bold")

FORBIDDEN_CHARS = [";", "--", "'", "*", "!"]  # simple garde-fou

# ========= Bouton arrondi (Canvas) =========
class RoundedButton(tk.Canvas):
    def __init__(
        self, parent, text, command=None,
        bg=PRIMARY, fg="white", hover_bg=None, active_bg=None,
        radius=20, padx=20, pady=10, font=FONT
    ):
        self.parent_bg = parent.cget("bg")
        super().__init__(parent, bg=self.parent_bg, highlightthickness=0, bd=0)

        self.text = text
        self.command = command
        self.color = bg
        self.fg = fg
        self.hover_color = hover_bg or bg
        self.active_color = active_bg or hover_bg or bg
        self.radius = radius
        self.padx = padx
        self.pady = pady
        self.font = tkfont.Font(font=font)

        tw = self.font.measure(text)
        th = self.font.metrics("linespace")
        self.w = tw + 2 * self.padx
        self.h = th + 2 * self.pady

        self.config(width=self.w, height=self.h, cursor="hand2")
        self.round_id = None
        self.text_id = None
        self._draw(self.color)

        self.bind("<Enter>", lambda e: self._draw(self.hover_color))
        self.bind("<Leave>", lambda e: self._draw(self.color))
        self.bind("<ButtonPress-1>", lambda e: self._draw(self.active_color))
        self.bind("<ButtonRelease-1>", self._on_release)

    def _rounded_rect_points(self, x1, y1, x2, y2, r):
        return [
            x1+r, y1,   x2-r, y1,   x2, y1,   x2, y1+r,
            x2, y2-r,   x2, y2,     x2-r, y2, x1+r, y2,
            x1, y2,     x1, y2-r,   x1, y1+r, x1, y1,
        ]

    def _draw(self, fill):
        self.delete("all")
        pts = self._rounded_rect_points(1, 1, self.w-1, self.h-1, self.radius)
        self.round_id = self.create_polygon(pts, smooth=True, splinesteps=36, fill=fill, outline=fill)
        self.text_id = self.create_text(self.w/2, self.h/2, text=self.text, fill=self.fg, font=self.font)

    def _on_release(self, _):
        self._draw(self.hover_color)
        if callable(self.command):
            self.command()

class EntryFormDialog:
    """Boîte modale thémée pour créer/éditer une entrée (service, identifiant, mot de passe)."""
    def __init__(self, root, title, service="", username="", password=""):
        self.result = None
        self.top = tk.Toplevel(root)
        self.top.title(title)
        self.top.configure(bg=CARD_COLOR)
        self.top.transient(root)
        self.top.grab_set()
        self.top.resizable(False, False)
        self.top.protocol("WM_DELETE_WINDOW", self._cancel)

        # Conteneur principal (carte)
        wrap = tk.Frame(self.top, bg=CARD_COLOR, padx=18, pady=18,
                        highlightbackground=BORDER, highlightthickness=1)
        wrap.pack(fill="both", expand=True)

        # --- Service
        tk.Label(wrap, text="Service", font=FONT, bg=CARD_COLOR, fg=SUBTEXT)\
            .grid(row=0, column=0, columnspan=2, sticky="w")
        self.service_entry = make_entry(wrap)
        if service:
            self.service_entry.delete(0, tk.END); self.service_entry.insert(0, service)
        self.service_entry.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(4, 10))

        # --- Identifiant
        tk.Label(wrap, text="Identifiant", font=FONT, bg=CARD_COLOR, fg=SUBTEXT)\
            .grid(row=2, column=0, columnspan=2, sticky="w")
        self.username_entry = make_entry(wrap)
        if username:
            self.username_entry.delete(0, tk.END); self.username_entry.insert(0, username)
        self.username_entry.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(4, 10))

        # --- Mot de passe + œil
        tk.Label(wrap, text="Mot de passe", font=FONT, bg=CARD_COLOR, fg=SUBTEXT)\
            .grid(row=4, column=0, columnspan=2, sticky="w")

        pw_row = tk.Frame(wrap, bg=CARD_COLOR)
        pw_row.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(4, 10))
        pw_row.grid_columnconfigure(0, weight=1)

        self.password_entry = make_entry(pw_row, show="*")
        if password:
            self.password_entry.delete(0, tk.END); self.password_entry.insert(0, password)
        self.password_entry.grid(row=0, column=0, sticky="ew")

        self._show_pw = tk.BooleanVar(master=self.top, value=False)
        def _toggle():
            self.password_entry.config(show="" if self._show_pw.get() else "*")

        RoundedButton(
            pw_row, "👁",
            command=lambda: (self._show_pw.set(not self._show_pw.get()), _toggle()),
            bg=ENTRY_BG, hover_bg="#374151", active_bg="#374151", fg=ENTRY_FG,
            radius=12, padx=10, pady=7, font=("Segoe UI", 11)
        ).grid(row=0, column=1, padx=(8, 0))

        def _gen_pw():
            new_pw = generate_password()
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, new_pw)
            self.password_entry.config(show="" if self._show_pw.get() else "*")

        RoundedButton(
            pw_row, "🔄 Générer",
            command=_gen_pw,
            bg=SECONDARY, hover_bg=SECONDARY_HOVER, fg="white",
            radius=12, padx=10, pady=7, font=("Segoe UI", 11)
        ).grid(row=0, column=2, padx=(8, 0))

        # --- Message d'erreur
        self.err = tk.Label(wrap, text="", font=("Segoe UI", 10), bg=CARD_COLOR, fg=DANGER)
        self.err.grid(row=6, column=0, columnspan=2, sticky="w")

        # --- Boutons
        btns = tk.Frame(wrap, bg=CARD_COLOR)
        btns.grid(row=7, column=0, columnspan=2, pady=(8, 0))
        RoundedButton(btns, "Annuler", self._cancel, bg=ENTRY_BG, hover_bg="#374151")\
            .pack(side="left", padx=6)
        RoundedButton(btns, "Valider", self._ok, bg=PRIMARY, hover_bg=PRIMARY_HOVER)\
            .pack(side="left", padx=6)

        # Mise en page
        wrap.grid_columnconfigure(0, weight=1)

        # Focus + raccourcis
        self.service_entry.focus_set()
        self.top.bind("<Return>", lambda e: self._ok())
        self.top.bind("<Escape>", lambda e: self._cancel())

        # Centre la fenêtre avec hauteur/largeur requises
        self._center_on_parent(root)

    def _center_on_parent(self, root):
        # S’assure que root a une taille valide
        root.update_idletasks()
        self.top.update_idletasks()

        req_w = max(520, self.top.winfo_reqwidth())
        req_h = self.top.winfo_reqheight()

        px, py = root.winfo_rootx(), root.winfo_rooty()
        pw, ph = max(root.winfo_width(), req_w), max(root.winfo_height(), req_h)

        x = px + (pw - req_w) // 2
        y = py + (ph - req_h) // 2

        self.top.geometry(f"{int(req_w)}x{int(req_h)}+{int(x)}+{int(y)}")

    def _ok(self):
        s  = self.service_entry.get().strip()
        u  = self.username_entry.get().strip()
        pw = self.password_entry.get().strip()
        if not s or not u or not pw:
            self.err.config(text="Tous les champs sont requis.")
            return
        self.result = (s, u, pw)
        self.top.destroy()

    def _cancel(self):
        self.result = None
        self.top.destroy()


def open_entry_form(root, title, service="", username="", password=""):
    dlg = EntryFormDialog(root, title, service, username, password)
    root.wait_window(dlg.top)
    return dlg.result


def open_entry_form(root, title, service="", username="", password=""):
    """Ouvre le dialogue et renvoie (service, username, password) ou None si annulé."""
    dlg = EntryFormDialog(root, title, service, username, password)
    root.wait_window(dlg.top)
    return dlg.result

# ========= Utilitaires =========
def clear_window(root):
    for widget in root.winfo_children():
        widget.destroy()
    root.configure(bg=BG_COLOR)

def make_entry(parent, width=34, show=None, placeholder=""):
    e = tk.Entry(
        parent, font=FONT, width=width,
        bg=ENTRY_BG, fg=ENTRY_FG, insertbackground=ENTRY_FG,
        relief="flat", highlightthickness=0, bd=0
    )
    if placeholder:
        e.insert(0, placeholder)
        e.config(fg=ENTRY_PLACEHOLD)
    if show:
        # ne masque pas le placeholder
        if placeholder:
            e.config(show="")
        else:
            e.config(show=show)

    def on_focus_in(_):
        if placeholder and e.get() == placeholder and e.cget("fg") == ENTRY_PLACEHOLD:
            e.delete(0, tk.END)
            e.config(fg=ENTRY_FG)
            if show:
                e.config(show=show)

    def on_focus_out(_):
        if placeholder and not e.get():
            e.insert(0, placeholder)
            e.config(fg=ENTRY_PLACEHOLD)
            if show:
                e.config(show="")
    e.bind("<FocusIn>", on_focus_in)
    e.bind("<FocusOut>", on_focus_out)
    return e

def build_centered_card(root, *, min_w=360, max_w=720, pad=24):
    """
    Conteneur centré et responsive.
    Retourne (page, card). Place tes widgets DANS 'card' avec grid/pack.
    """
    root.configure(bg=BG_COLOR)

    # Conteneur plein écran
    page = tk.Frame(root, bg=BG_COLOR)
    page.pack(fill="both", expand=True)

    # La carte qu’on centre avec .place(..., anchor="center")
    card = tk.Frame(page, bg=CARD_COLOR, padx=20, pady=20,
                    highlightbackground=BORDER, highlightthickness=1)
    card.grid_columnconfigure(0, weight=1)  # widgets internes s’étirent
    card.place(relx=0.5, rely=0.5, anchor="center")

    def _apply_width(w):
        avail = max(min_w, min(max_w, w - 2*pad))
        card.configure(width=avail)

    # largeur initiale (sans attendre un resize)
    page.update_idletasks()
    _apply_width(page.winfo_width())

    # ajuste à chaque redimensionnement
    def _on_resize(ev):
        _apply_width(ev.width)
        # on reste parfaitement centré
        card.place_configure(relx=0.5, rely=0.5, anchor="center")

    page.bind("<Configure>", _on_resize)

    return page, card


# ========= ÉCRANS =========
def show_login_screen(root):
    clear_window(root)
    # Charge et affiche l'image de fond
    bg_path = "src/background.png"  # Mets le nom de ton image ici
    img = Image.open(bg_path)
    img = img.resize((root.winfo_width(), root.winfo_height()), Image.Resampling.LANCZOS)
    bg_img = ImageTk.PhotoImage(img)
    bg_label = tk.Label(root, image=bg_img)
    bg_label.image = bg_img  # Garde une référence
    bg_label.place(x=0, y=0, relwidth=1, relheight=1)

    _, card = build_centered_card(root)
    card.lift()  # S'assure que la carte est au-dessus de l'image

    tk.Label(card, text="🔐 Gestionnaire de Mots de Passe",
             font=TITLE_FONT, bg=CARD_COLOR, fg=TEXT)\
        .grid(row=0, column=0, sticky="w", pady=(0, 12))

    tk.Label(card, text="Nom d'utilisateur", font=FONT, bg=CARD_COLOR, fg=SUBTEXT)\
        .grid(row=1, column=0, sticky="w")
    username_entry = make_entry(card, placeholder="email@domaine.com")
    username_entry.grid(row=2, column=0, sticky="ew", pady=(4, 12))

    tk.Label(card, text="Mot de passe maître", font=FONT, bg=CARD_COLOR, fg=SUBTEXT)\
        .grid(row=3, column=0, sticky="w")
    pw_row = tk.Frame(card, bg=CARD_COLOR)
    pw_row.grid(row=4, column=0, sticky="ew", pady=(4, 12))
    pw_row.grid_columnconfigure(0, weight=1)

    password_entry = make_entry(pw_row, show="*", placeholder="••••••••")
    password_entry.grid(row=0, column=0, sticky="ew")

    show_pw = tk.BooleanVar(master=root, value=False)

    def toggle_pw():
        if password_entry.cget("fg") != ENTRY_PLACEHOLD:
            password_entry.config(show="" if show_pw.get() else "*")

    RoundedButton(
        pw_row, "👁", lambda: (show_pw.set(not show_pw.get()), toggle_pw()),
        bg=ENTRY_BG, hover_bg="#374151", active_bg="#374151", fg=ENTRY_FG,
        radius=12, padx=10, pady=7, font=("Segoe UI", 11)
    ).grid(row=0, column=1, padx=(8, 0))

    btns = tk.Frame(card, bg=CARD_COLOR)
    btns.grid(row=5, column=0, pady=(6, 0))
    RoundedButton(btns, "Se connecter",
                  lambda: _attempt_login(username_entry, password_entry),
                  bg=PRIMARY, hover_bg=PRIMARY_HOVER)\
        .grid(row=0, column=0, pady=(0, 8))
    RoundedButton(btns, "Créer un compte",
                  lambda: show_registration_screen(root),
                  bg=SECONDARY, hover_bg=SECONDARY_HOVER)\
        .grid(row=1, column=0)

def _attempt_login(username_entry, password_entry):
    username = username_entry.get().strip()
    password = password_entry.get()
    if authenticate_user(username, password):
        messagebox.showinfo("Succès", "Connexion réussie.")
        show_dashboard(username_entry.winfo_toplevel())
    else:
        messagebox.showerror("Erreur", "Échec de la connexion.")

def show_registration_screen(root):
    clear_window(root)
    _, card = build_centered_card(root)

    header = tk.Frame(card, bg=CARD_COLOR)
    header.grid(row=0, column=0, sticky="ew")
    RoundedButton(header, "← Retour", lambda: show_login_screen(root),
                  bg=ENTRY_BG, hover_bg="#374151")\
        .pack(side="left")

    tk.Label(card, text="🆕 Créer un compte",
             font=TITLE_FONT, bg=CARD_COLOR, fg=TEXT)\
        .grid(row=1, column=0, sticky="w", pady=(8, 12))

    tk.Label(card, text="Nom d'utilisateur", font=FONT, bg=CARD_COLOR, fg=SUBTEXT)\
        .grid(row=2, column=0, sticky="w")
    username_entry = make_entry(card, placeholder="email@domaine.com")
    username_entry.grid(row=3, column=0, sticky="ew", pady=(4, 10))

    tk.Label(card, text="Mot de passe maître", font=FONT, bg=CARD_COLOR, fg=SUBTEXT)\
        .grid(row=4, column=0, sticky="w")
    password_entry = make_entry(card, show="*", placeholder="••••••••")
    password_entry.grid(row=5, column=0, sticky="ew", pady=(4, 10))

    tk.Label(card, text="Confirmer le mot de passe", font=FONT, bg=CARD_COLOR, fg=SUBTEXT)\
        .grid(row=6, column=0, sticky="w")
    confirm_entry = make_entry(card, show="*", placeholder="••••••••")
    confirm_entry.grid(row=7, column=0, sticky="ew", pady=(4, 10))

    def attempt_registration():
        username = username_entry.get().strip()
        password = password_entry.get()
        confirm  = confirm_entry.get()
        if password != confirm:
            messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas.")
            return
        if create_user(username, password):
            messagebox.showinfo("Succès", "Compte créé. Vous pouvez maintenant vous connecter.")
            show_login_screen(root)
        else:
            messagebox.showerror("Erreur", "Échec de la création du compte.")

    RoundedButton(card, "Créer le compte", attempt_registration,
                  bg=PRIMARY, hover_bg=PRIMARY_HOVER)\
        .grid(row=8, column=0, pady=(6, 0))

def show_dashboard(root, search_query=""):
    clear_window(root)
    _, card = build_centered_card(root, max_w=900)

    tk.Label(card, text=f"👋 Bienvenue {SESSION['username']}",
             font=TITLE_FONT, bg=CARD_COLOR, fg=TEXT)\
        .grid(row=0, column=0, sticky="n", pady=(0, 8))

    actions = tk.Frame(card, bg=CARD_COLOR)
    actions.grid(row=1, column=0, pady=(0, 8))
    RoundedButton(actions, "➕ Ajouter une entrée", lambda: add_entry(root),
                  bg=PRIMARY, hover_bg=PRIMARY_HOVER)\
        .pack(side="left", padx=6)
    RoundedButton(actions, "🚪 Déconnexion", lambda: [logout(), show_login_screen(root)],
                  bg=DANGER, hover_bg=DANGER_HOVER)\
        .pack(side="left", padx=6)

    # Recherche
    search_bar = tk.Frame(card, bg=CARD_COLOR)
    search_bar.grid(row=2, column=0, sticky="ew", pady=(4, 6))
    search_bar.grid_columnconfigure(1, weight=1)
    tk.Label(search_bar, text="🔎 Rechercher :", font=FONT, bg=CARD_COLOR, fg=TEXT)\
        .grid(row=0, column=0, sticky="w", padx=(0, 8))
    search_var = tk.StringVar(card, value=search_query)
    e_search = make_entry(search_bar)
    e_search.delete(0, tk.END); e_search.insert(0, search_var.get())
    e_search.grid(row=0, column=1, sticky="ew")
    e_search.bind("<KeyRelease>", lambda _e: show_dashboard(root, e_search.get().strip()))

    # Correction ici : on utilise search_var et on passe sa valeur à show_dashboard
    def on_search(_e):
        search_text = e_search.get().strip()
        show_dashboard(root, search_text)
    e_search.bind("<KeyRelease>", on_search)

    RoundedButton(search_bar, "Réinitialiser",
                  lambda: [e_search.delete(0, tk.END), show_dashboard(root, "")],
                  bg=SECONDARY, hover_bg=SECONDARY_HOVER, radius=16, padx=14, pady=6, font=("Segoe UI", 11))\
        .grid(row=0, column=2, padx=(8, 0))

    # Liste
    list_frame = tk.Frame(card, bg=CARD_COLOR)
    list_frame.grid(row=3, column=0, sticky="ew", pady=(6, 0))
    list_frame.grid_columnconfigure(0, weight=1)

    entries = get_entries(SESSION["user_id"])
    key = SESSION["encryption_key"]

    found = 0
    for row in entries:
        (entry_id, service_ct, username_ct, password_ct,
         nonce_s, tag_s, nonce_u, tag_u, nonce_p, tag_p) = row
        try:
            service = decrypt_data(key, service_ct, nonce_s, tag_s).decode()
            username = decrypt_data(key, username_ct, nonce_u, tag_u).decode()
            password = decrypt_data(key, password_ct, nonce_p, tag_p).decode()
        except Exception:
            service = "[Erreur de déchiffrement]"; username = password = ""

        if search_query and search_query.lower() not in service.lower():
            continue
        found += 1

        item = tk.Frame(list_frame, bg=CARD_COLOR, padx=12, pady=12,
                        highlightbackground=BORDER, highlightthickness=1)
        item.grid(sticky="ew", pady=8)
        item.grid_columnconfigure(0, weight=1)

        tk.Label(item, text=f"🔐 Service : {service}", font=FONT, bg=CARD_COLOR, fg=TEXT)\
            .grid(row=0, column=0, sticky="w")
        tk.Label(item, text=f"👤 Identifiant : {username}", font=FONT, bg=CARD_COLOR, fg=SUBTEXT)\
            .grid(row=1, column=0, sticky="w")
        tk.Label(item, text=f"🔑 Mot de passe : {'*' * len(password)}", font=FONT, bg=CARD_COLOR, fg=SUBTEXT)\
            .grid(row=2, column=0, sticky="w")

        # boutons à droite
        btns = tk.Frame(item, bg=CARD_COLOR)
        btns.grid(row=0, column=1, rowspan=3, sticky="e")

        def show_password_temporarily(p=password):
            popup = tk.Toplevel(root)
            popup.title("Mot de passe")
            popup.configure(bg=CARD_COLOR)
            popup.geometry("300x120")
            popup.resizable(False, False)
            tk.Label(popup, text=f"🔑 {p}", font=FONT, bg=CARD_COLOR, fg=TEXT).pack(pady=12)
            def copy_to_clipboard():
                popup.clipboard_clear(); popup.clipboard_append(p); popup.update()
                messagebox.showinfo("Copié", "Mot de passe copié dans le presse-papiers.")
            RoundedButton(popup, "📋 Copier", copy_to_clipboard,
                          bg=SECONDARY, hover_bg=SECONDARY_HOVER,
                          radius=16, padx=14, pady=6, font=("Segoe UI", 11)).pack()
            popup.after(5000, popup.destroy)

        RoundedButton(btns, "Afficher", show_password_temporarily,
                      bg=SECONDARY, hover_bg=SECONDARY_HOVER,
                      radius=16, padx=14, pady=6, font=("Segoe UI", 11))\
            .pack(side="right", padx=6)

        def confirm_delete(eid=entry_id):
            if messagebox.askyesno("Confirmer", "Supprimer cette entrée ?"):
                delete_entry(eid); show_dashboard(root, e_search.get().strip())

        RoundedButton(btns, "Supprimer", confirm_delete,
                      bg=DANGER, hover_bg=DANGER_HOVER,
                      radius=16, padx=14, pady=6, font=("Segoe UI", 11))\
            .pack(side="right", padx=6)

        def edit_dialog(eid=entry_id, old_s=service, old_u=username, old_p=password):
            vals = open_entry_form(root, "Modifier l'entrée", old_s, old_u, old_p)
            if vals is None:
                return
            ns, nu, np = vals

            if any(c in ns for c in FORBIDDEN_CHARS) or any(c in nu for c in FORBIDDEN_CHARS):
                messagebox.showerror("Caractères interdits", "Les champs ne doivent pas contenir ';', '--' ou des apostrophes.")
                return

            k = SESSION["encryption_key"]
            s_ct, nsn, tgs = encrypt_data(k, ns.encode())
            u_ct, nun, tgu = encrypt_data(k, nu.encode())
            p_ct, npn, tgp = encrypt_data(k, np.encode())
            update_entry(eid, s_ct, u_ct, p_ct, nsn, tgs, nun, tgu, npn, tgp)
            messagebox.showinfo("Succès", "Entrée modifiée.")
            show_dashboard(root)


        RoundedButton(btns, "Modifier", edit_dialog,
                      bg=PRIMARY, hover_bg=PRIMARY_HOVER,
                      radius=16, padx=14, pady=6, font=("Segoe UI", 11))\
            .pack(side="right", padx=6)

    if found == 0:
        tk.Label(card, text="Aucun service ne correspond à votre recherche.",
                 font=FONT, bg=CARD_COLOR, fg=SUBTEXT)\
            .grid(row=4, column=0, sticky="n", pady=(8, 0))

# ========= Ajout d’une entrée =========
def add_entry(root):
    vals = open_entry_form(root, "Ajouter une entrée")
    if vals is None:
        return
    service, username, password = vals

    if any(c in service for c in FORBIDDEN_CHARS) or any(c in username for c in FORBIDDEN_CHARS):
        log_attempt("Tentative d'injection détectée", service, username)
        messagebox.showerror("Caractères interdits", "Les champs ne doivent pas contenir ';', '--','!'ou des apostrophes.")
        return

    k = SESSION["encryption_key"]
    s_ct, ns, ts = encrypt_data(k, service.encode())
    u_ct, nu, tu = encrypt_data(k, username.encode())
    p_ct, np, tp = encrypt_data(k, password.encode())

    insert_entry(SESSION["user_id"], s_ct, u_ct, p_ct, ns, ts, nu, tu, np, tp)
    messagebox.showinfo("Succès", "Entrée ajoutée.")
    show_dashboard(root)


def log_attempt(message, service="", username=""):
    with open("security_log.txt", "a", encoding="utf-8") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {message} | Service: {service} | Identifiant: {username}\n")

# ========= Lancement =========
def launch_gui():
    root = tk.Tk()
    root.title("🔐 Gestionnaire de Mots de Passe")
    root.geometry("1040x640")   # résizable; tout est centré et responsive
    root.minsize(720, 520)
    show_login_screen(root)
    root.mainloop()
