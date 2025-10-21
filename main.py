import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from mnemonic import Mnemonic
from bip32utils import BIP32Key
import hashlib


class SeedPhraseGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("Bitcoin Seed Phrase Generator")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # Инициализация mnemonic
        self.mnemo = Mnemonic("english")
        
        # Создание интерфейса
        self.create_widgets()
        
    def create_widgets(self):
        # Заголовок
        title_label = tk.Label(
            self.root, 
            text="Генератор Seed Фраз Bitcoin",
            font=("Arial", 16, "bold"),
            pady=10
        )
        title_label.pack()
        
        # Фрейм для ввода слов
        input_frame = tk.LabelFrame(
            self.root,
            text="Введите первые 11 слов seed фразы",
            font=("Arial", 12),
            padx=10,
            pady=10
        )
        input_frame.pack(padx=10, pady=10, fill="x")
        
        # Создание 11 полей ввода
        self.word_entries = []
        for i in range(11):
            row_frame = tk.Frame(input_frame)
            row_frame.pack(fill="x", pady=2)
            
            label = tk.Label(
                row_frame,
                text=f"Слово {i+1}:",
                width=10,
                anchor="w"
            )
            label.pack(side="left", padx=5)
            
            entry = tk.Entry(row_frame, width=20, font=("Arial", 10))
            entry.pack(side="left", padx=5)
            self.word_entries.append(entry)
        
        # Кнопка генерации
        button_frame = tk.Frame(self.root)
        button_frame.pack(pady=10)
        
        generate_btn = tk.Button(
            button_frame,
            text="Сгенерировать",
            command=self.generate_phrases,
            font=("Arial", 12, "bold"),
            bg="#4CAF50",
            fg="white",
            padx=20,
            pady=10,
            cursor="hand2"
        )
        generate_btn.pack(side="left", padx=5)
        
        clear_btn = tk.Button(
            button_frame,
            text="Очистить",
            command=self.clear_all,
            font=("Arial", 12),
            padx=20,
            pady=10,
            cursor="hand2"
        )
        clear_btn.pack(side="left", padx=5)
        
        # Прогресс бар
        self.progress = ttk.Progressbar(
            self.root,
            orient="horizontal",
            length=300,
            mode="determinate"
        )
        self.progress.pack(pady=5)
        
        # Область вывода результатов
        output_frame = tk.LabelFrame(
            self.root,
            text="Результаты (128 валидных seed фраз)",
            font=("Arial", 12),
            padx=10,
            pady=10
        )
        output_frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.WORD,
            width=100,
            height=20,
            font=("Courier", 9)
        )
        self.output_text.pack(fill="both", expand=True)
        
    def validate_words(self, words):
        """Проверка валидности введенных слов"""
        wordlist = self.mnemo.wordlist
        for i, word in enumerate(words):
            if word.strip() not in wordlist:
                return False, f"Слово {i+1} '{word}' не найдено в BIP39 словаре"
        return True, ""
    
    def generate_phrases(self):
        """Генерация 128 валидных seed фраз"""
        # Очистка вывода
        self.output_text.delete(1.0, tk.END)
        self.progress["value"] = 0
        self.root.update_idletasks()
        
        # Получение введенных слов
        input_words = [entry.get().strip().lower() for entry in self.word_entries]
        
        # Проверка на пустые поля
        if any(not word for word in input_words):
            messagebox.showerror("Ошибка", "Все 11 полей должны быть заполнены!")
            return
        
        # Валидация слов
        is_valid, error_msg = self.validate_words(input_words)
        if not is_valid:
            messagebox.showerror("Ошибка", error_msg)
            return
        
        # Получение списка всех возможных слов для 12-го слова
        wordlist = self.mnemo.wordlist
        valid_phrases = []
        
        # Перебор слов для нахождения 128 валидных фраз
        self.output_text.insert(tk.END, "Генерация валидных фраз...\n\n")
        self.root.update_idletasks()
        
        count = 0
        for word in wordlist:
            if count >= 128:
                break
                
            # Создание полной фразы
            full_phrase = ' '.join(input_words + [word])
            
            # Проверка валидности фразы
            if self.mnemo.check(full_phrase):
                valid_phrases.append(full_phrase)
                count += 1
                
                # Обновление прогресса
                self.progress["value"] = (count / 128) * 100
                self.root.update_idletasks()
        
        if len(valid_phrases) < 128:
            messagebox.showwarning(
                "Предупреждение",
                f"Найдено только {len(valid_phrases)} валидных фраз из 128 возможных"
            )
        
        # Вывод результатов
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Сгенерировано {len(valid_phrases)} валидных seed фраз:\n")
        self.output_text.insert(tk.END, "="*100 + "\n\n")
        
        for idx, phrase in enumerate(valid_phrases, 1):
            try:
                # Генерация seed из мнемоники
                seed = self.mnemo.to_seed(phrase, passphrase="")
                
                # Генерация master key
                master_key = BIP32Key.fromEntropy(seed)
                
                # Получение адреса и ключей (BIP44 путь для Bitcoin: m/44'/0'/0'/0/0)
                # m/44'/0'/0'/0/0 - стандартный путь для первого адреса Bitcoin
                child_key = master_key.ChildKey(44 + 2**31)  # 44'
                child_key = child_key.ChildKey(0 + 2**31)     # 0' (Bitcoin)
                child_key = child_key.ChildKey(0 + 2**31)     # 0' (аккаунт)
                child_key = child_key.ChildKey(0)              # 0 (внешняя цепь)
                child_key = child_key.ChildKey(0)              # 0 (первый адрес)
                
                # Получение адреса и приватного ключа
                address = child_key.Address()
                private_key_wif = child_key.WalletImportFormat()
                public_key = child_key.PublicKey().hex()
                
                # Вывод информации
                self.output_text.insert(tk.END, f"#{idx}\n")
                self.output_text.insert(tk.END, f"Мнемоника: {phrase}\n")
                self.output_text.insert(tk.END, f"12-е слово: {phrase.split()[-1]}\n")
                self.output_text.insert(tk.END, f"Адрес (m/44'/0'/0'/0/0): {address}\n")
                self.output_text.insert(tk.END, f"Приватный ключ (WIF): {private_key_wif}\n")
                self.output_text.insert(tk.END, f"Публичный ключ: {public_key}\n")
                self.output_text.insert(tk.END, "-"*100 + "\n\n")
                
            except Exception as e:
                self.output_text.insert(tk.END, f"Ошибка при генерации для фразы #{idx}: {str(e)}\n\n")
        
        self.progress["value"] = 100
        messagebox.showinfo("Успех", f"Генерация завершена! Создано {len(valid_phrases)} фраз.")
    
    def clear_all(self):
        """Очистка всех полей и вывода"""
        for entry in self.word_entries:
            entry.delete(0, tk.END)
        self.output_text.delete(1.0, tk.END)
        self.progress["value"] = 0


def main():
    root = tk.Tk()
    app = SeedPhraseGenerator(root)
    root.mainloop()


if __name__ == "__main__":
    main()

