# Что это такое?

Это SOCKS5 прокси-сервер для обхода блокировок
[Роскомнадзора](https://eng.rkn.gov.ru/), которое поставляется в виде
приложения для запуска в системном лотке (tray) или сервера для запуска в консоли.

# Как это работает?

Загружается список заблокированных IP адресов из
[API Роскомсвободы](https://reestr.rublacklist.net/article/api/)
и запускается специальный SOCKS5 прокси-сервер со специальной функцией подключения.
Эта функция проверяет к какому IP-адресу выполняется подключение: если IP
заблокирован, то подключение выполняется через [Tor](https://www.torproject.org/);
а если IP не заблокирован, то — напрямую.

Таким образом скорость подключения и передачи данных к не заблокированным
ресурсам остается на прежнем уровне, а заблокированные ресурсы становятся
доступными.

Tor-сервер встроен в исполняемые файлы и, при их запуске, распаковывается в
текущую директорию.

# Где скачать?

Приложение и сервер доступны для скачивания в скомпилированном виде в
[разделе релизов](https://github.com/dimuls/rkn-bypasser/releases).

# Как пользоваться?

## Приложение `rkn-bypasser-tray.exe`

1. Запустить исполняемый файл.
2. Дождаться когда прокси-сервер запуститься.
3. Настроить в браузере (или в другом приложении) подключение через SOCKS5-прокси
где, в качестве адреса, указать `127.0.0.1:8000`.

## Сервер `rkn-bypasser.exe`

Вывод справки:
```
rkn-bypasser.exe --help
Usage:
  rkn-bypasser [flags]

Flags:
      --config string           config file (default is ./rkn-bypasser.yaml)
  -h, --help                    help for rkn-bypasser
      --listen-address string   proxy server listen address (default "127.0.0.1:8000")
      --tor-args stringArray    tor args to use (default [--quiet])
      --tor-path string         tor path (default "tor")
      --torrc string            torrc file path
```

Пример запуска с флагами:
```
rkn-bypasser.exe --listen-address 0.0.0.0:8000 --tor-args --quite,--help --tor-path tor --torrc path\to\torrc
```

Конфиг файл в формате yaml. Пример конфига:
```
listen-address: 0.0.0.0:8000
tor-args:
    - --quite
    - --help
tor-path: tor
torrc: path\to\torrc
```

# Есть вопросы?

Пишите мне на:

* Email: dimuls@yandex.ru
* Telegram: @dimuls

Буду рад помочь=)
