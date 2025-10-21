#!/bin/bash

echo "🚀 Запуск Bitcoin Seed Generator (Web Version)..."
echo ""

# Проверка наличия Python
if ! command -v python3 &> /dev/null
then
    echo "❌ Python3 не найден. Установите Python3 и попробуйте снова."
    exit 1
fi

# Создание виртуального окружения, если его нет
if [ ! -d "venv" ]; then
    echo "📦 Создание виртуального окружения..."
    python3 -m venv venv
fi

# Активация виртуального окружения
echo "🔧 Активация виртуального окружения..."
source venv/bin/activate

# Установка зависимостей
echo "📦 Установка зависимостей..."
pip install -q -r requirements.txt

# Запуск веб-сервера
echo ""
echo "="*60
echo "✅ Запуск веб-сервера..."
echo "="*60
echo ""
python app.py

