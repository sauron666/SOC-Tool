SOC Tool – Унфицирано приложение за анализ, разузнаване и реакция на инциденти - подпомага рутинните проверки на SOC анализатори L1 и L2

**SOC GUI Tool** е графично Python приложение, разработено за нуждите на Security Operations Center (SOC) екипи. Инструментът обединява множество функции за разследване на инциденти, OSINT, мрежов анализ, сканиране на IP адреси, Active Directory диагностика, PowerShell автоматизация и др.

Основни функции

IP & URL анализ
- Геолокация и ISP информация (ip-api, geojs, findip, ipinfo.io, maxmind и др.)
- Reputation check чрез AbuseIPDB, VirusTotal, HybridAnalysis
- Многопоточна пакетна проверка на IP адреси
- Поддръжка на прокси сървъри

OSINT
- Интеграция с Hunter.io, Shodan, crt.sh, PublicWWW
- Проверка на изтекли пароли чрез BreachDirectory и HaveIbeenpwned
- Проверка на социални профили по потребителско име

Файл анализ
- Drag & Drop на файлове
- VirusTotal и Hybrid-Analysis сканиране на fajlove

Мрежови инструменти
- Пинг, Traceroute, Continuous Ping to multiple ip adresses
- UDP & TCP порт сканиране с banner detection
- Многопоточност за бързина и стабилност

Active Directory
- Lockout статус
- Извличане на потребители, OU и групи чрез LDAP (SSPI auth)
- Работи без нужда от администраторски креденшъли

PowerShell GUI конзола
- Изпълнение на PS команди чрез pypsrp
- Drag & Drop на `.ps1` скриптове
- Основни команди за по бързо изпълнение

IOC & Threat таб
- Търсене на информация по IOC
- Извличане на IP, домейни, хешове, URL от файл - pdf, csv, docx, exl
- Проверка в mxtoolbox
- Шаблони за изготвяне на фишинг доклади
- Автоматично докладване фишинг url до google и microsoft
---

Инсталация

Стартиране с команда python SOC_Tool.py

Изисквания

- Python 3.9+
- pip зависимости:
pip install -r requirements.txt
