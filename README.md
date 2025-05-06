# 🛡️ FormSec

**FormSec** is a lightweight PHP library that evaluates the security level of incoming requests or payloads. It uses a point-based system starting at 100 and deducts points based on various threat indicators.

## 📦 Installation

Install via [Composer](https://getcomposer.org/):

`composer require kowalskidawid/formsec`

## 🚀 Quick Start
```
use FormSec\Chercker;

$checker = new Chercker('192.168.1.1', 'email@example.com', 'my message');
$score = $checker->check();
```

## ⚙️ How It Works
Each instance of FormSec starts with a security score of 100. Points are subtracted if a threat is detected according to the following rules:

Condition	Constant	Deduction
IP is likely a VPN	-50

Domain found on certificate alerts list	-40

IP matches known server providers	-20

Domain is newly registered	-20

XSS attempt detected	-40

Example
```
$checker = new Checker('xxx.xxx.xxx.xxx', 'contact@suspicious-domain.com', '<script>alert(1)</script>');
echo $$checker->check(); // 100 - 40 - 40 = 20
```

## 📄 License
This project is licensed under the MIT License.

Contributions and issue reports are welcome!
