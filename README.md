# DomainScope

Pasif domain OSINT araci. Python 3.9+, **bagimlilik yok**.

## Ozellikler
- DNS kayitlari (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA) - Google DoH uzerinden
- Sertifika seffafligi (crt.sh) ile alt alan adi kesfi ve IP cozumleme
- RDAP kayit bilgileri (olusturma/bitis tarihi, durum)
- HTTP guvenlik basligi kontrolu ve TLS bilgisi
- JSON veya Markdown rapor ciktisi

## Kullanim
```bash
python domainscope.py example.com
python domainscope.py example.com -o report.md
python domainscope.py example.com -o report.json --no-resolve
```

| Parametre | Aciklama |
|-----------|----------|
| `-o`, `--output` | Raporu dosyaya yazar (`.json` veya `.md`) |
| `--no-resolve` | Alt alan adlarinin IP cozumlemesini atlar |

## Yasal Uyari
Yalnizca herkese acik veri kaynaklarini kullanir ve saldiri trafigi gondermez. Sadece arastirma yapmaya yetkili oldugunuz domainlerde kullanin.

## Yol Haritasi
- Wayback Machine URL gecmisi
- SPF/DMARC e-posta analizi
- ASN / IP konum bilgisi
- HTML rapor

## Lisans
MIT
