# VulnLab: Kasıtlı olarak AÇIKLI yazılmış eğitim amaçlı web uygulaması.
# UYARI: Bu kodu asla internete açık bir sunucuda çalıştırma! Sadece kendi bilgisayarında (127.0.0.1) çalışır.

import sqlite3
from pathlib import Path

from flask import Flask, render_template, request, session, redirect, url_for

BASE = Path(__file__).parent
DB_PATH = BASE / "vulnlab.db"

app = Flask(__name__)
app.secret_key = "egitim-amacli-gizli-anahtar"  # oturum çerezlerini imzalamak için (gerçek projede rastgele ve gizli olmalı)


# ---------------------------------------------------------------- Veritabanı
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # satırlara row["kullanici_adi"] diye erişebilmek için
    return conn


def init_db():
    """Her başlatmada veritabanını sıfırdan kurar, böylece denemelerin kalıcı bir şeyi bozmaz."""
    DB_PATH.unlink(missing_ok=True)
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE kullanicilar (
                id INTEGER PRIMARY KEY,
                kullanici_adi TEXT NOT NULL,
                sifre TEXT NOT NULL,
                rol TEXT NOT NULL,
                gizli_not TEXT NOT NULL
            )
        """)
        conn.executemany(
            "INSERT INTO kullanicilar (kullanici_adi, sifre, rol, gizli_not) VALUES (?, ?, ?, ?)",
            [
                # id=1 admin, id=2 ceylin, id=3 ahmet  (Seviye 3 IDOR için id'ler önemli)
                ("admin", "Xk9#mQ2$vL7!pR4z", "yönetici", "Sunucu kurtarma kodu: ROOT-9931-SECRET"),
                ("ceylin", "kedi2024", "kullanıcı", "Kredi kartı son 4 hane: 4821"),
                ("ahmet", "ahmet123", "kullanıcı", "Ev adresi: Ornek Mah. 12. Sok. No:3"),
            ],
        )
        # Seviye 2 (XSS): Kullanıcıların birbirine mesaj bıraktığı pano
        conn.execute("""
            CREATE TABLE mesajlar (
                id INTEGER PRIMARY KEY,
                yazar TEXT NOT NULL,
                icerik TEXT NOT NULL
            )
        """)
        conn.execute(
            "INSERT INTO mesajlar (yazar, icerik) VALUES (?, ?)",
            ("ahmet", "Herkese merhaba! Bu panoya mesaj bırakabilirsiniz."),
        )


# ---------------------------------------------------------------- Sayfalar
@app.route("/", methods=["GET", "POST"])
def login():
    hata = None
    sorgu = None

    if request.method == "POST":
        kullanici_adi = request.form.get("kullanici_adi", "")
        sifre = request.form.get("sifre", "")

        # ❌ ESKİ (AÇIK): Girdi doğrudan SQL metninin içine yapıştırılıyordu. SQL Injection'a açıktı.
        #    sorgu = f"SELECT * FROM kullanicilar WHERE kullanici_adi = '{kullanici_adi}' AND sifre = '{sifre}'"
        #
        # ✅ YENİ (GÜVENLİ): Parametreli sorgu. Komutun yapısı sabit; '?' yerine gelen değerler
        #    HER ZAMAN veri olarak işlenir, asla komut olarak çalışmaz. Tırnak artık zararsız.
        sorgu = "SELECT * FROM kullanicilar WHERE kullanici_adi = ? AND sifre = ?"

        try:
            with get_db() as conn:
                kullanici = conn.execute(sorgu, (kullanici_adi, sifre)).fetchone()
        except sqlite3.Error as e:
            kullanici = None
            hata = f"Veritabanı hatası: {e}"

        if kullanici:
            session["id"] = kullanici["id"]
            session["kullanici_adi"] = kullanici["kullanici_adi"]
            session["rol"] = kullanici["rol"]
            return redirect(url_for("panel"))
        if not hata:
            hata = "Kullanıcı adı veya şifre hatalı."

    # Eğitim amaçlı: çalıştırılan SQL sorgusunu ekranda gösteriyoruz (gerçek bir sitede asla yapılmaz)
    return render_template("login.html", hata=hata, sorgu=sorgu)


@app.route("/panel")
def panel():
    if "kullanici_adi" not in session:
        return redirect(url_for("login"))
    return render_template("panel.html", kullanici_adi=session["kullanici_adi"], rol=session["rol"])


@app.route("/mesajlar", methods=["GET", "POST"])
def mesajlar():
    if "kullanici_adi" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        icerik = request.form.get("icerik", "").strip()
        if icerik:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO mesajlar (yazar, icerik) VALUES (?, ?)",
                    (session["kullanici_adi"], icerik),
                )
        return redirect(url_for("mesajlar"))

    with get_db() as conn:
        kayitlar = conn.execute("SELECT yazar, icerik FROM mesajlar ORDER BY id").fetchall()
    return render_template("mesajlar.html", kayitlar=kayitlar)


@app.route("/hesap/<int:kid>")
def hesap(kid):
    if "kullanici_adi" not in session:
        return redirect(url_for("login"))

    # ❌ ESKİ (AÇIK): İstenen 'kid' numarasının giriş yapan kişiye ait olup olmadığı
    #    hiç kontrol edilmiyordu; herkes /hesap/<baska-numara> ile başkasının notunu görebiliyordu.
    #
    # ✅ YENİ (GÜVENLİ): Yetkilendirme kontrolü. Kullanıcı yalnızca KENDİ hesabını görebilir.
    #    Yöneticiler (rol == "yönetici") istisna; onlar tüm hesaplara erişebilir.
    if kid != session["id"] and session["rol"] != "yönetici":
        return "Bu hesabi goruntuleme yetkiniz yok.", 403

    with get_db() as conn:
        kullanici = conn.execute(
            "SELECT kullanici_adi, gizli_not FROM kullanicilar WHERE id = ?", (kid,)
        ).fetchone()

    if not kullanici:
        return "Boyle bir hesap yok.", 404
    return render_template("hesap.html", hesap=kullanici, kid=kid)


@app.route("/cikis")
def cikis():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    # host="127.0.0.1": uygulama SADECE senin bilgisayarından erişilebilir, ağdaki başka kimse ulaşamaz.
    # debug=False: Flask'ın hata ayıklama modu, sayfadan kod çalıştırmaya izin verdiği için kapalı.
    app.run(host="127.0.0.1", port=5000, debug=False)
