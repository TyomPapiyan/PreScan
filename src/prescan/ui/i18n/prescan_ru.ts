<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE TS>
<TS version="2.1" language="ru_RU">
<context>
    <name>AboutPage</name>
    <message>
        <location filename="../qml/pages/AboutPage.qml" line="11"/>
        <source>About PreScan</source>
        <translation>О программе PreScan</translation>
    </message>
    <message>
        <location filename="../qml/pages/AboutPage.qml" line="17"/>
        <source>PreScan is not an antivirus and does not replace your system&apos;s protection. The verdict is informational. The decision to run a file is yours.</source>
        <translation>PreScan не является антивирусом и не заменяет штатную защиту системы. Вердикт носит информационный характер. Ответственность за запуск файла лежит на пользователе.</translation>
    </message>
    <message>
        <location filename="../qml/pages/AboutPage.qml" line="24"/>
        <source>Built with Qt / PySide6 (LGPLv3), YARA-X, LIEF, oletools, pikepdf. RinUI (MIT) is vendored in ui/vendor/RinUI. The malware classifier and its feature extractor derive from the EMBER2024 project (Apache-2.0). Full licenses are in the licenses/ folder. ClamAV is used as an external process, not linked.</source>
        <translation>Собрано на Qt / PySide6 (LGPLv3), YARA-X, LIEF, oletools, pikepdf. RinUI (MIT) вендорится в ui/vendor/RinUI. Классификатор вредоносности и его экстрактор признаков основаны на проекте EMBER2024 (Apache-2.0). Полные лицензии — в папке licenses/. ClamAV вызывается как внешний процесс, без линковки.</translation>
    </message>
    <message>
        <location filename="../qml/pages/AboutPage.qml" line="38"/>
        <source>PySide6 / Qt are used under the LGPLv3. Corresponding source: </source>
        <translation>PySide6 / Qt используются на условиях LGPLv3. Исходный код: </translation>
    </message>
    <message>
        <location filename="../qml/pages/AboutPage.qml" line="46"/>
        <source>Google Safe Browsing and the VirusTotal public API are free for non-commercial use only.</source>
        <translation>Google Safe Browsing и публичный API VirusTotal бесплатны только для некоммерческого использования.</translation>
    </message>
</context>
<context>
    <name>Bridge</name>
    <message>
        <location filename="../bridge.py" line="244"/>
        <source>ML model: %1% likely malicious</source>
        <extracomment>URL-scan sources that receive the FULL URL, vs Safe Browsing (hash-prefix).</extracomment>
        <translation>ML-модель: %1% вероятность вредоносности</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="245"/>
        <source>ML model could not score the file</source>
        <translation>ML-модель не смогла оценить файл</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="271"/>
        <source>Downloading the ML model…</source>
        <translation>Загрузка ML-модели…</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="275"/>
        <source>Model download failed: %1</source>
        <translation>Не удалось загрузить модель: %1</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="277"/>
        <source>ML model installed.</source>
        <translation>ML-модель установлена.</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="288"/>
        <source>Updating ClamAV databases…</source>
        <translation>Обновление баз ClamAV…</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="292"/>
        <source>ClamAV update failed: %1</source>
        <translation>Не удалось обновить ClamAV: %1</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="305"/>
        <source>Downloading YARA rules…</source>
        <translation>Загрузка правил YARA…</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="309"/>
        <source>Rule update failed: %1</source>
        <translation>Не удалось обновить правила: %1</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="311"/>
        <source>Installed %1 YARA rule file(s).</source>
        <translation>Установлено файлов правил YARA: %1</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="616"/>
        <source>Ready</source>
        <translation>Готово</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="617"/>
        <source>Add an API key in Settings</source>
        <translation>Добавьте API-ключ в настройках</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="618"/>
        <source>Rules not downloaded — update rules</source>
        <translation>Правила не загружены — обновите правила</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="619"/>
        <source>ML model not installed</source>
        <translation>ML-модель не установлена</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="620"/>
        <source>Not installed</source>
        <translation>Не установлено</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="621"/>
        <source>Source temporarily unavailable (offline)</source>
        <translation>Источник временно недоступен (офлайн)</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="622"/>
        <source>Source temporarily unavailable</source>
        <translation>Источник временно недоступен</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="623"/>
        <source>Not available on this OS</source>
        <translation>Недоступно в этой ОС</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="624"/>
        <source>Disabled</source>
        <translation>Отключено</translation>
    </message>
    <message>
        <location filename="../bridge.py" line="625"/>
        <source>File too large for this engine</source>
        <translation>Файл слишком большой для этого движка</translation>
    </message>
</context>
<context>
    <name>HistoryPage</name>
    <message>
        <location filename="../qml/pages/HistoryPage.qml" line="25"/>
        <source>History</source>
        <translation>История</translation>
    </message>
    <message>
        <location filename="../qml/pages/HistoryPage.qml" line="28"/>
        <source>Clear history</source>
        <translation>Очистить историю</translation>
    </message>
    <message>
        <location filename="../qml/pages/HistoryPage.qml" line="36"/>
        <source>Verdict:</source>
        <translation>Вердикт:</translation>
    </message>
    <message>
        <location filename="../qml/pages/HistoryPage.qml" line="45"/>
        <source>Search by name or SHA-256…</source>
        <translation>Поиск по имени или SHA-256…</translation>
    </message>
    <message>
        <location filename="../qml/pages/HistoryPage.qml" line="89"/>
        <source>Clear history?</source>
        <translation>Очистить историю?</translation>
    </message>
    <message>
        <location filename="../qml/pages/HistoryPage.qml" line="92"/>
        <source>This permanently deletes all scan history entries.</source>
        <translation>Это безвозвратно удалит все записи истории проверок.</translation>
    </message>
</context>
<context>
    <name>Main</name>
    <message>
        <location filename="../qml/Main.qml" line="12"/>
        <source>PreScan</source>
        <translation>PreScan</translation>
    </message>
    <message>
        <location filename="../qml/Main.qml" line="72"/>
        <source>Scan</source>
        <translation>Сканирование</translation>
    </message>
    <message>
        <location filename="../qml/Main.qml" line="72"/>
        <source>History</source>
        <translation>История</translation>
    </message>
    <message>
        <location filename="../qml/Main.qml" line="72"/>
        <source>Quarantine</source>
        <translation>Карантин</translation>
    </message>
    <message>
        <location filename="../qml/Main.qml" line="73"/>
        <source>Settings</source>
        <translation>Настройки</translation>
    </message>
    <message>
        <location filename="../qml/Main.qml" line="73"/>
        <source>About</source>
        <translation>О программе</translation>
    </message>
</context>
<context>
    <name>QuarantinePage</name>
    <message>
        <location filename="../qml/pages/QuarantinePage.qml" line="14"/>
        <source>Restore to folder</source>
        <translation>Восстановить в папку</translation>
    </message>
    <message>
        <location filename="../qml/pages/QuarantinePage.qml" line="23"/>
        <source>Restore this file?</source>
        <translation>Восстановить этот файл?</translation>
    </message>
    <message>
        <location filename="../qml/pages/QuarantinePage.qml" line="29"/>
        <source>Warning: this file was quarantined as dangerous. Restoring it puts the original malware back on disk. Continue only if you are sure.</source>
        <translation>Внимание: этот файл помещён в карантин как опасный. Восстановление вернёт исходную вредоносную программу на диск. Продолжайте, только если уверены.</translation>
    </message>
    <message>
        <location filename="../qml/pages/QuarantinePage.qml" line="39"/>
        <source>Delete permanently?</source>
        <translation>Удалить безвозвратно?</translation>
    </message>
    <message>
        <location filename="../qml/pages/QuarantinePage.qml" line="42"/>
        <source>This permanently deletes the quarantined file.</source>
        <translation>Это безвозвратно удалит файл из карантина.</translation>
    </message>
    <message>
        <location filename="../qml/pages/QuarantinePage.qml" line="49"/>
        <source>Quarantine</source>
        <translation>Карантин</translation>
    </message>
    <message>
        <location filename="../qml/pages/QuarantinePage.qml" line="52"/>
        <source>Quarantine is empty.</source>
        <translation>Карантин пуст.</translation>
    </message>
    <message>
        <location filename="../qml/pages/QuarantinePage.qml" line="79"/>
        <source>Restore</source>
        <translation>Восстановить</translation>
    </message>
    <message>
        <location filename="../qml/pages/QuarantinePage.qml" line="83"/>
        <source>Re-scan</source>
        <translation>Перепроверить</translation>
    </message>
    <message>
        <location filename="../qml/pages/QuarantinePage.qml" line="87"/>
        <source>Delete</source>
        <translation>Удалить</translation>
    </message>
</context>
<context>
    <name>ScanPage</name>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="23"/>
        <source>Choose a file to scan</source>
        <translation>Выберите файл для проверки</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="52"/>
        <source>File</source>
        <translation>Файл</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="53"/>
        <source>Link</source>
        <translation>Ссылка</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="105"/>
        <source>⬇

Drop a file here, or use the button below

exe · msi · dll · apk · pdf · docx · zip · 7z …</source>
        <translation>⬇

Перетащите файл сюда или нажмите кнопку ниже

exe · msi · dll · apk · pdf · docx · zip · 7z …</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="112"/>
        <source>Choose a file from the computer</source>
        <translation>Выбрать файл с компьютера</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="118"/>
        <source>No size limit · local analysis</source>
        <translation>Без ограничений по размеру · локальная проверка</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="126"/>
        <source>Download and scan the file (into a temp folder)</source>
        <translation>Скачать и проверить файл (во временную папку)</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="127"/>
        <source>Follow the redirect chain</source>
        <translation>Проверять цепочку редиректов</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="130"/>
        <source>Scan the link</source>
        <translation>Проверить ссылку</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="149"/>
        <source>Analysing…</source>
        <translation>Анализируем…</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="152"/>
        <source>Cancel</source>
        <translation>Отмена</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="177"/>
        <source>Incomplete scan — some sources were unavailable</source>
        <translation>Проверка неполная — часть источников недоступна</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="180"/>
        <source>WHY THIS VERDICT</source>
        <translation>ПОЧЕМУ ТАКОЙ ВЕРДИКТ</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="188"/>
        <source>Save report…</source>
        <translation>Сохранить отчёт…</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="189"/>
        <source>Quarantine</source>
        <translation>Карантин</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="191"/>
        <source>New scan</source>
        <translation>Новая проверка</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="197"/>
        <source>HTML report (*.html)</source>
        <translation>Отчёт HTML (*.html)</translation>
    </message>
    <message>
        <location filename="../qml/pages/ScanPage.qml" line="197"/>
        <source>PDF report (*.pdf)</source>
        <translation>Отчёт PDF (*.pdf)</translation>
    </message>
</context>
<context>
    <name>SettingsPage</name>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="30"/>
        <source>Settings</source>
        <translation>Настройки</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="35"/>
        <source>Local engines</source>
        <translation>Локальные движки</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="40"/>
        <source>Update YARA rules</source>
        <translation>Обновить правила YARA</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="42"/>
        <source>Update ClamAV databases</source>
        <translation>Обновить базы ClamAV</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="44"/>
        <source>Download ML model</source>
        <translation>Скачать ML-модель</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="45"/>
        <source>Re-check</source>
        <translation>Проверить снова</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="64"/>
        <source>API keys</source>
        <translation>API-ключи</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="84"/>
        <source>key configured — enter to replace</source>
        <translation>ключ задан — введите новый, чтобы заменить</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="85"/>
        <source>paste API key</source>
        <translation>вставьте API-ключ</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="88"/>
        <source>Save</source>
        <translation>Сохранить</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="93"/>
        <source>Check key</source>
        <translation>Проверить ключ</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="110"/>
        <source>Privacy</source>
        <translation>Приватность</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="118"/>
        <source>When you scan a link, the FULL URL is sent to these sources:</source>
        <translation>При проверке ссылки ПОЛНЫЙ URL отправляется этим источникам:</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="131"/>
        <source>Google Safe Browsing receives only truncated hash prefixes — never the full URL.</source>
        <translation>Google Safe Browsing получает только усечённые hash-префиксы — никогда полный URL.</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="134"/>
        <source>Never upload files to the cloud</source>
        <translation>Никогда не загружать файлы в облако</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="142"/>
        <source>Cloud file upload is not available in this version — files never leave your machine.</source>
        <translation>Загрузка файлов в облако в этой версии недоступна — файлы не покидают вашу машину.</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="145"/>
        <source>Send only hashes</source>
        <translation>Отправлять только хеши</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="153"/>
        <source>When on, links are checked only by Safe Browsing hash prefixes — a green (safe) verdict for a URL is not possible.</source>
        <translation>При включении ссылки проверяются только по хеш-префиксам Safe Browsing — зелёный (безопасный) вердикт по ссылке невозможен.</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="156"/>
        <source>Disable all network activity</source>
        <translation>Отключить всю сетевую активность</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="166"/>
        <source>Scanning</source>
        <translation>Сканирование</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="171"/>
        <source>Download size limit (MB):</source>
        <translation>Лимит размера загрузки (МБ):</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="176"/>
        <source>Scan timeout (s):</source>
        <translation>Тайм-аут проверки (с):</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="181"/>
        <source>Archive extraction depth:</source>
        <translation>Глубина распаковки архивов:</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="186"/>
        <source>Cache TTL (days):</source>
        <translation>Срок жизни кэша (дней):</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="197"/>
        <source>Interface</source>
        <translation>Интерфейс</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="201"/>
        <source>Theme:</source>
        <translation>Тема:</translation>
    </message>
    <message>
        <location filename="../qml/pages/SettingsPage.qml" line="209"/>
        <source>Language:</source>
        <translation>Язык:</translation>
    </message>
</context>
<context>
    <name>SignalCard</name>
    <message>
        <location filename="../qml/components/SignalCard.qml" line="31"/>
        <source>weight %1</source>
        <translation>вес %1</translation>
    </message>
</context>
</TS>
