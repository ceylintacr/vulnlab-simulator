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

## Yol haritası
- [x] Seviye 1 — SQL Injection
- [ ] Seviye 2 — XSS (Cross-Site Scripting)
- [ ] Seviye 3 — IDOR (yetkisiz veri erişimi)
- [ ] Seviye 4 — Zayıf şifre saklama (hash & bcrypt)

## Teknolojiler
Python, Flask, SQLite
