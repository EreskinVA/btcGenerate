#!/bin/bash

echo "🚀 Запуск Bitcoin Seed Generator..."
echo ""

# Проверка наличия Python
if ! command -v python3 &> /dev/null
then
    echo "❌ Python3 не найден. Установите Python3 и попробуйте снова."
    exit 1
fi

# Проверка наличия Tkinter
if ! python3 -c "import tkinter" &> /dev/null
then
    echo "⚠️  Tkinter не найден!"
    echo "Установите его командой: brew install python-tk@3.13"
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

# Проверка и установка зависимостей
echo "📦 Установка зависимостей..."
pip install -r requirements.txt --quiet

# Запуск программы
echo "✅ Запуск программы..."
python main.py

