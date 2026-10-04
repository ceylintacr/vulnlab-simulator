# VulnLab — Zafiyetli Web Uygulaması & Sızma Testi Laboratuvarı

Kasıtlı olarak güvenlik açıkları barındıran, eğitim amaçlı bir web uygulaması. Her açık **önce istismar ediliyor**, ardından **güvenli sürümü** yazılıyor. Amaç, yaygın web zafiyetlerinin hem saldıran (offensive) hem savunan (defensive) tarafını uygulamalı öğrenmek.

> ⚠️ **Uyarı:** Bu uygulama bilerek açıklıdır. Yalnızca `127.0.0.1` (yerel bilgisayar) üzerinde çalışır ve asla internete açık bir sunucuda çalıştırılmamalıdır. Yalnızca kendi makinende, öğrenme amacıyla kullan.

## Kurulum

```bash
pip install flask
python app.py
```

Sonra tarayıcıda `http://127.0.0.1:5000` adresini aç. Veritabanı her başlangıçta sıfırlanır; denemeler kalıcı bir şeyi bozmaz.

## Test kullanıcıları

| Kullanıcı adı | Şifre | Rol |
|---|---|---|
| admin | (güçlü, gizli) | yönetici |
| ceylin | kedi2024 | kullanıcı |
| ahmet | ahmet123 | kullanıcı |

---

## Seviye 1: SQL Injection

### Açık
Giriş sorgusu, kullanıcının yazdığı metni doğrudan SQL cümlesinin içine yapıştırıyordu. Böylece **veri** ile **komut** iç içe geçiyor ve girdi SQL'in yapısını değiştirebiliyordu.

### İstismar
Kullanıcı adı alanına şu değerler yazılarak, admin şifresi **bilinmeden** yönetici girişi yapılabiliyordu:

```
admin' --
' OR 1=1 --
```

`admin' --` örneğinde oluşan sorgu:
```sql
SELECT * FROM kullanicilar WHERE kullanici_adi = 'admin' --' AND sifre = '...'
```
Girilen `'` sunucunun tırnağını erkenden kapatır, `--` ise şifre kontrolünü yoruma çevirip devre dışı bırakır.

### Çözüm: Parametreli sorgu (prepared statement)

```python
# ❌ Açık: girdi doğrudan SQL metnine gömülüyor
sorgu = f"SELECT * FROM kullanicilar WHERE kullanici_adi = '{kullanici_adi}' AND sifre = '{sifre}'"
kullanici = conn.execute(sorgu).fetchone()

# ✅ Güvenli: komutun yapısı sabit, '?' değerleri her zaman veri olarak işlenir
sorgu = "SELECT * FROM kullanicilar WHERE kullanici_adi = ? AND sifre = ?"
kullanici = conn.execute(sorgu, (kullanici_adi, sifre)).fetchone()
```

Parametreli sorguda veritabanı önce cümlenin yapısını sabitler; `?` yerine gelen değerler asla komut olarak çalıştırılmaz. Böylece tırnak ve `--` gibi karakterler zararsız birer metne dönüşür.

### Doğrulama
| Girdi | Açık sürüm | Güvenli sürüm |
|---|---|---|
| `admin' --` | 🚩 Yönetici girişi | ❌ Reddedildi |
| `' OR 1=1 --` | 🚩 Giriş | ❌ Reddedildi |
| `ceylin` / `kedi2024` | ✅ Giriş | ✅ Giriş |
| `admin` / gerçek şifre | ✅ Giriş | ✅ Giriş |

---

## Seviye 2: XSS (Cross-Site Scripting)

### Açık
Mesaj panosu, kullanıcıların yazdığı mesajları `{{ icerik | safe }}` ile basıyordu. Jinja2'deki `| safe` filtresi, Flask'ın otomatik HTML kaçışını **devre dışı bırakır**. Böylece mesaja gömülen HTML/JavaScript, o sayfayı açan herkesin tarayıcısında çalışır. Zararlı kod veritabanında saklandığı için bu bir **Stored XSS**'tir.

### İstismar
Mesaj alanına yazılan şu girdiler, panoyu açan herkeste çalışır:

```html
<script>alert('XSS')</script>
<img src=x onerror="document.body.style.background='crimson';document.title='HACKED'">
```

`<img onerror>` yöntemi, sayfa yüklendikten sonra eklenen `<script>` etiketlerinin çalışmaması sorununu aştığı için XSS testlerinde tercih edilir.

### Çözüm: Otomatik HTML kaçışı

```html
<!-- ❌ Açık: '| safe' otomatik kaçışı kapatır -->
<p>{{ icerik | safe }}</p>

<!-- ✅ Güvenli: Flask <, >, " karakterlerini otomatik kaçırır; girdi kod değil, metin olarak görünür -->
<p>{{ icerik }}</p>
```

### Doğrulama
| Girdi | Açık sürüm | Güvenli sürüm |
|---|---|---|
| `<script>...</script>` | 🚩 Kod çalışır | ❌ `&lt;script&gt;` olarak metin görünür |
| `<img onerror=...>` | 🚩 Kod çalışır | ❌ Metin olarak görünür |
| Normal mesaj | ✅ Görünür | ✅ Görünür |

### SQL Injection ile ortak nokta
Her iki açık da **veri ile komutun birbirine karışmasından** doğar: SQLi'de girdi veritabanı sorgusuna, XSS'te ise HTML sayfasına karışır. Çözüm de aynıdır: veriyi komuttan ayrı tutmak (parametreli sorgu / otomatik kaçış).

---

## Seviye 3: IDOR (Insecure Direct Object Reference)

### Açık
"Hesabım" sayfası, adresteki numarayla (`/hesap/<id>`) doğrudan veri çekiyordu ama bu numaranın giriş yapan kullanıcıya ait olup olmadığını **kontrol etmiyordu**. Bu bir **yetkilendirme (authorization) eksikliğidir**.

### İstismar
`ceylin` (id=2) olarak giriş yapıp adresteki numarayı değiştirmek, başka kullanıcıların gizli verisini açığa çıkarır:

| Adres | Sonuç |
|---|---|
| `/hesap/2` | Kendi bilgisi (normal) |
| `/hesap/1` | 🚩 admin'in gizli kurtarma kodu |
| `/hesap/3` | 🚩 ahmet'in ev adresi |

Hiçbir özel girdi veya kod gerekmez; yalnızca URL'deki sayı değiştirilir.

### Çözüm: Yetkilendirme (sahiplik) kontrolü

```python
# ❌ Açık: istenen kaydın sahibi kim, kontrol edilmiyor
kullanici = conn.execute("SELECT ... WHERE id = ?", (kid,)).fetchone()

# ✅ Güvenli: kullanıcı yalnızca kendi kaydına erişebilir (yönetici istisna)
if kid != session["id"] and session["rol"] != "yönetici":
    return "Bu hesabi goruntuleme yetkiniz yok.", 403
```

### Doğrulama
| Kullanıcı | İstek | Açık sürüm | Güvenli sürüm |
|---|---|---|---|
| ceylin | `/hesap/2` (kendi) | 200 | 200 |
| ceylin | `/hesap/1` (admin) | 🚩 200 | 403 |
| ceylin | `/hesap/3` (ahmet) | 🚩 200 | 403 |
| admin | `/hesap/2` | 200 | 200 (yönetici istisnası) |

### Öncekilerden farkı
SQLi ve XSS, **girdinin işlenmesindeki** hatadan doğar; çözümleri girdiyi güvenli işlemektir. IDOR ise **eksik bir yetki kontrolünden** doğar; girdide bir sorun yoktur, sunucunun "bu veriye erişim hakkın var mı?" sorusunu sorması gerekir.

---

## Yol haritası
- [x] Seviye 1 — SQL Injection
- [x] Seviye 2 — XSS (Cross-Site Scripting)
- [x] Seviye 3 — IDOR (yetkisiz veri erişimi)
- [ ] Seviye 4 — Zayıf şifre saklama (hash & bcrypt)

## Teknolojiler
Python, Flask, SQLite
