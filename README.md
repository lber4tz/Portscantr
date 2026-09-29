PortScan

PortScan, ağ üzerindeki belirli bir hedefte portların durumunu kontrol etmek için geliştirilmiş bir Python projesidir.

Amaç

Bu proje, ağ güvenliği ve port tarama mantığını öğrenmek amacıyla geliştirilmiştir.

Özellikler

- Portları kontrol etme
- Açık portları tespit etme
- Terminal üzerinden sonuçları gösterme
- Python ile geliştirilmiştir
- ip adresinden konum gösterme
- nmap taraması
Gereksinimler

- Python 3
- Kali Linux veya Python çalıştırabilen bir sistem

Çalıştırma

Projeyi indirdikten ve klonladıktan sonra proje klasörüne girin:

cd portscan

Ardından:

python3 portscan.py

nmap modül hatası alırsanız yüklemelisiniz.
pip install python-nmap

sudo apt update && sudo apt install python3-nmap -y

Nmap'ın Sistemde kurulu oldugundan emin olun 
|
sudo apt install nmap -y

Güvenlik ve yasal kullanım

Bu araç yalnızca kendi sistemlerinizde veya tarama yapmak için açıkça izin aldığınız sistemlerde kullanılmalıdır. İzinsiz sistemleri taramak yasal veya etik olmayabilir.