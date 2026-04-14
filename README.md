# NodeShift VPN — Android App

Flutter-клиент для VPN-сервиса на базе Xray / VLESS Reality.

## Стек

- Flutter 3.22+
- `flutter_v2ray` — VPN-туннель
- `go_router` — навигация
- `dio` — HTTP + куки
- `flutter_animate` — анимации
- YooKassa — приём платежей

## Быстрый старт

### 1. Конфигурация

```bash
cp lib/config/app_config.dart lib/config/app_config.local.dart
```

Открой `app_config.local.dart` и заполни:

```dart
const kBase   = 'https://your-server.com';   // URL бэкенда
const kScheme = 'yourapp';                   // deep-link схема
const kBotId  = '123456789';                 // числовой ID Telegram-бота
```

Также поправь `android/app/src/main/AndroidManifest.xml`:
- `your-server.com` → твой домен
- `yourapp` → твой deep-link scheme (должен совпадать с `kScheme`)

### 2. Установка зависимостей

```bash
flutter pub get
```

### 3. Сборка

```bash
# Debug APK
flutter build apk --debug

# Release APK (по архитектурам, меньший размер)
flutter build apk --release --split-per-abi
```

APK: `build/app/outputs/flutter-apk/`

## Структура

```
lib/
├── config/          # app_config.dart — настройки (URL, Bot ID)
├── models/          # UserModel, SubModel, PlanModel, ServerModel
├── services/
│   ├── api.dart     # HTTP-клиент (Dio + cookie auth)
│   └── vpn_service.dart
├── screens/
│   ├── auth/        # Email + Telegram OAuth
│   ├── home/        # Главный экран, подключение, серверы
│   ├── payment/     # Оплата подписки (YooKassa)
│   └── profile/
├── router/          # go_router + deep-link обработчики
├── theme/           # Цвета и тёмная тема
└── widgets/         # NsButton, NsField
```

## Требования к бэкенду

Приложение ожидает REST API:

| Метод | Путь | Описание |
|-------|------|----------|
| POST | `/api/auth/mobile-login` | Отправить код на email |
| POST | `/api/auth/verify-login` | Подтвердить код → сессия |
| GET  | `/api/auth/tg-mobile/exchange?code=` | Обменять TG OAuth код |
| GET  | `/api/auth/me` | Текущий пользователь |
| GET  | `/api/user/subscription` | Подписка и серверы |
| GET  | `/api/payment/plans` | Список тарифов |
| POST | `/api/payment/create` | Создать платёж |
| GET  | `/api/payment/status/{id}` | Статус платежа |

## Лицензия

MIT — см. [LICENSE](LICENSE)
