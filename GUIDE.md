# NodeShift VPN — Руководство разработчика

## Быстрый старт

### macOS / Linux
```bash
# Клонируйте репозиторий, перейдите в папку
cd nodeshift-app

# Запустите скрипт установки (Flutter + Android SDK + первая сборка)
chmod +x scripts/setup_mac.sh
./scripts/setup_mac.sh
```

### Windows
```powershell
# В PowerShell от администратора:
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\setup_windows.ps1
```

После завершения: `NodeShift-debug.apk` в корне проекта.

---

## Полная установка вручную

### 1. Установка Flutter

**macOS / Linux:**
```bash
# Скачиваем Flutter 3.22.2
curl -Lo ~/flutter.zip https://storage.googleapis.com/flutter_infra_release/releases/stable/macos/flutter_macos_arm64-3.22.2-stable.zip
unzip ~/flutter.zip -d ~/
export PATH="$HOME/flutter/bin:$PATH"

# Добавить в ~/.zshrc или ~/.bashrc:
echo 'export PATH="$HOME/flutter/bin:$PATH"' >> ~/.zshrc
```

**Windows:**
1. Скачайте [Flutter SDK](https://docs.flutter.dev/get-started/install/windows)
2. Распакуйте в `C:\flutter`
3. Добавьте `C:\flutter\bin` в PATH (Системные переменные)

### 2. Android Studio + Эмулятор

**Рекомендуемый эмулятор**: Android Studio Emulator (лучший для тестирования)

1. Скачайте [Android Studio](https://developer.android.com/studio)
2. При установке выберите: Android SDK, Android Emulator, Intel HAXM
3. В Android Studio: **Tools → Device Manager → Create Device**
   - Устройство: **Pixel 7** (хорошо отображает приложения)
   - Система: **Android 14 (API 34) — Google Play**
4. Запустите эмулятор кнопкой ▶

```bash
# Проверить что эмулятор виден
adb devices
# Должно быть: emulator-5554   device
```

### 3. Настройка Android SDK

```bash
# Установить компоненты (если не через Android Studio)
sdkmanager "platforms;android-34" "build-tools;34.0.0" "platform-tools"

# Принять лицензии
flutter doctor --android-licenses
```

### 4. Первый запуск

```bash
cd nodeshift-app
flutter pub get

# Запуск на эмуляторе (hot reload)
flutter run

# Или сборка APK
./scripts/build.sh debug
```

---

## Структура проекта

```
nodeshift-app/
├── lib/
│   ├── main.dart                    # Точка входа
│   ├── models/
│   │   └── models.dart              # UserModel, SubModel
│   ├── services/
│   │   ├── api.dart                 # HTTP клиент, Telegram OAuth
│   │   └── vpn_service.dart         # Xray/V2Ray управление
│   ├── screens/
│   │   ├── splash.dart              # Проверка авторизации
│   │   ├── onboarding.dart          # 3-шаговое введение
│   │   ├── auth/
│   │   │   ├── auth_screen.dart     # TG + email кнопки
│   │   │   ├── email_login.dart     # Вход по email + код
│   │   │   └── email_register.dart  # Регистрация + код
│   │   ├── home/
│   │   │   └── home_screen.dart     # Главный экран + VPN кнопка
│   │   └── profile/
│   │       └── profile_screen.dart  # Профиль, выход
│   ├── router/
│   │   └── router.dart              # go_router навигация + deep link
│   ├── theme/
│   │   └── app_theme.dart           # Цвета, темы
│   └── widgets/
│       ├── ns_button.dart           # Кнопки
│       └── ns_field.dart            # Текстовые поля
├── android/
│   ├── app/
│   │   ├── build.gradle
│   │   └── src/main/
│   │       ├── AndroidManifest.xml  # Deep links, permissions
│   │       └── kotlin/.../
│   │           └── MainActivity.kt  # Chrome Custom Tab + deep link
│   └── build.gradle
├── assets/
│   └── icon.png                     # Иконка приложения (1024×1024)
├── scripts/
│   ├── setup_mac.sh                 # Полная установка macOS/Linux
│   ├── setup_windows.ps1            # Полная установка Windows
│   ├── build.sh                     # Быстрая сборка
│   └── gen_icon.py                  # Генерация иконок всех размеров
└── .github/workflows/
    └── build-apk.yml                # CI/CD: автосборка APK
```

---

## Авторизация

### Telegram OAuth (основной способ)
1. Нажмите «Войти через Telegram»
2. Открывается Chrome Custom Tab с `oauth.telegram.org`
3. Пользователь подтверждает в Telegram
4. Сайт `nodeshift.space/tg-mobile-cb` верифицирует хэш
5. Редирект на `nodeshift://auth?code=XXX`
6. Приложение перехватывает deep link
7. Обменивает code на сессию через `/api/auth/tg-mobile/exchange`
8. Устанавливаются cookie, пользователь попадает на главный экран

### Email (резервный)
- Вход: email → код на почту → верификация
- Регистрация: email + пароль → код на почту → верификация

---

## VPN (Xray / V2Ray)

Приложение использует `flutter_v2ray` — пакет который включает Xray core
как нативные `.so` библиотеки Android.

```dart
// Подключение
await VpnService().connect(vlessLink);

// Отключение
await VpnService().disconnect();

// Статус
VpnService().status  // VpnStatus.connected / disconnected / ...
```

VLESS ссылка берётся из API `/api/user/subscription` → поле `vless_link`.

---

## Сборка APK

### Debug (для тестирования)
```bash
./scripts/build.sh
# или
flutter build apk --debug
# → build/app/outputs/flutter-apk/app-debug.apk
```

### Release (для публикации)
```bash
./scripts/build.sh release
# или
flutter build apk --release

# С подписью (нужен keystore):
flutter build apk --release \
  --keystore=keystore.jks \
  --keystore-password=YOUR_PASS \
  --key-alias=nodeshift \
  --key-password=YOUR_PASS
```

### Установить на телефон
```bash
# Включить отладку по USB на телефоне
adb install NodeShift-debug.apk

# Или напрямую через USB
adb -s DEVICE_ID install NodeShift-debug.apk
```

---

## Рекомендуемые эмуляторы

| Эмулятор | Плюсы | Минусы |
|----------|-------|--------|
| **Android Studio** (✅ рекомендуем) | Официальный, hot reload, profiler | Требует много RAM |
| **Genymotion** | Быстрый, много конфигураций | Платный для коммерческого |
| **BlueStacks** | Простой | Не поддерживает ADB нормально |

**Лучший выбор**: Android Studio Emulator с Pixel 7, API 34.

### Установка Android Studio Emulator
```bash
# macOS
brew install --cask android-studio

# После установки Android Studio:
# Tools → Device Manager → + → Pixel 7 → Android 14 API 34
```

---

## Генерация иконки

Поместите файл `assets/icon.png` (1024×1024, RGBA PNG):
```bash
pip install Pillow
python3 scripts/gen_icon.py
```

Сгенерирует иконки для всех плотностей экрана Android.

---

## CI/CD

При push в `main` → GitHub Actions собирает debug APK.
При создании тега `v*` → собирает release APK и публикует в GitHub Releases.

```bash
git tag v1.0.0
git push origin v1.0.0
```

---

## Переменные для production

В `lib/services/api.dart`:
```dart
const kBase  = 'https://nodeshift.space';   // API сервер
const kBotId = '8035304453';                 // Telegram Bot ID
```

---

## Troubleshooting

**`flutter doctor` показывает ошибки Android SDK:**
```bash
flutter config --android-sdk ~/android-sdk
flutter doctor --android-licenses
```

**Эмулятор не запускается (Intel HAXM):**
```bash
# macOS
brew install intel-haxm
# или включить в BIOS: Virtualization Technology (VT-x)
```

**Ошибка `SDK location not found`:**
```bash
# Создайте android/local.properties:
echo "sdk.dir=$HOME/android-sdk" > android/local.properties
echo "flutter.sdk=$HOME/flutter" >> android/local.properties
```

**Deep link не работает:**
- Проверьте что в `AndroidManifest.xml` есть intent-filter для `nodeshift://auth`
- На эмуляторе: `adb shell am start -W -a android.intent.action.VIEW -d "nodeshift://auth?code=TEST" space.nodeshift.vpn`
