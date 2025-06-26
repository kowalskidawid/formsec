# FormSec – Zabezpieczenie Formularzy w PHP

FormSec to biblioteka napisana w PHP służąca do zabezpieczania formularzy internetowych przed spamem, botami i innymi zagrożeniami. Idealna dla stron kierowanych do użytkowników polskojęzycznych.

## 📦 Instalacja

FormSec można zainstalować za pomocą [Composera](https://getcomposer.org):

composer require kowalskidawid/formsec
🛠 Wymagania
PHP 5.6 lub nowszy

Co najmniej 50MB wolnego miejsca

Otwarty dostęp wychodzący na porty: 43, 80, 443

🚀 Szybki start
php
Copy
Edit
use FormSec\Checker;

$checker = new Checker($message, $email, ['/path/to/file1.txt', '/path/to/file2.txt']);
$checker->check();
$score = $checker->getScore();

if ($score < 40) {
    // Zgłoszenie uznane za niebezpieczne
}
🧠 Jak to działa?
FormSec analizuje:

Treść wiadomości (język, złośliwe linki, skrypty XSS)

IP nadawcy

Wiek domeny e-mail

Użycie proxy/VPN

Bazy danych CERT Polska

Załączniki (skan przez VirusTotal)

Na podstawie tych danych przydziela wynik punktowy 0–100. Im niższy wynik, tym większe podejrzenie zagrożenia.

Wynik	Ocena
80–100	Bezpieczna wiadomość
40–79	Prawdopodobnie bezpieczna
< 40	Ryzykowna / zablokowana

💡 Zastosowanie
Formularze kontaktowe

Formularze komentarzy

Formularze zgłoszeń nadużyć / błędów

Treści w językach opartych na cyrylicy (np. rosyjski, ukraiński)

✅ Zalety
Skuteczna ochrona przed spamem i botami

Zmniejszenie liczby fałszywych zgłoszeń

Poprawa jakości danych i komfortu użytkownika

⚠️ Zagrożenia i ograniczenia
Możliwe fałszywe alarmy (false positives)

Wymaga aktualizacji – brak może obniżyć skuteczność

Zależność od zewnętrznych usług (np. RIPE, VirusTotal)

🧰 Rozwiązywanie problemów
Błąd	Możliwe rozwiązanie
Connection timed out	Sprawdź firewalla i otwarte porty
php_network_getaddresses	Skonfiguruj DNS (np. /etc/resolv.conf)
open_basedir restriction	Sprawdź konfigurację open_basedir
Failed to open stream	Sprawdź uprawnienia i dostęp do katalogu vendor
file could not be downloaded	Upewnij się, że allow_url_fopen jest włączone

🌐 Strona projektu
🔗 https://formsec.pl

📄 Licencja
Projekt dostępny na licencji MIT.

Autor: Dawid Kowalski
Repozytorium: github.com/kowalskidawid/formsec
