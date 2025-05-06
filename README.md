# 🛡️ FormSec

**FormSec** is a lightweight PHP library that evaluates the security level of incoming requests or payloads. It uses a point-based system starting at 100 and deducts points based on various threat indicators.

## 📦 Installation

Install via [Composer](https://getcomposer.org/):

`composer require kowalskidawid/formsec`

## 🚀 Quick Start
```
use FormSec\Chercker;

$checker = new Chercker();
$score = $checker->check('192.168.1.1', 'email@example.com', 'my message');
```

## 📄 License
This project is licensed under the MIT License.

Contributions and issue reports are welcome!
