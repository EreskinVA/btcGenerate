from flask import Flask, render_template, request, jsonify
from mnemonic import Mnemonic
from bip32utils import BIP32Key
import hashlib
import bech32
import lmdb
import os

app = Flask(__name__)
mnemo = Mnemonic("english")

def hash160(data):
    """RIPEMD160(SHA256(data))"""
    h = hashlib.new('ripemd160')
    h.update(hashlib.sha256(data).digest())
    return h.digest()

def pubkey_to_p2wpkh_address(pubkey):
    """Конвертирует публичный ключ в P2WPKH адрес (Native SegWit, bc1...)"""
    pubkey_hash = hash160(pubkey)
    converted = bech32.convertbits(pubkey_hash, 8, 5)
    return bech32.bech32_encode('bc', [0] + converted)

def pubkey_to_p2sh_p2wpkh_address(pubkey):
    """Конвертирует публичный ключ в P2SH-P2WPKH адрес (SegWit, 3...)"""
    pubkey_hash = hash160(pubkey)
    # OP_0 <20-byte-hash>
    witness_program = b'\x00\x14' + pubkey_hash
    script_hash = hash160(witness_program)
    # Версия 0x05 для P2SH
    versioned = b'\x05' + script_hash
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return base58_encode(versioned + checksum)

def base58_encode(data):
    """Base58 кодирование"""
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(data, 'big')
    encoded = ''
    while num > 0:
        num, remainder = divmod(num, 58)
        encoded = alphabet[remainder] + encoded
    # Добавляем leading zeros
    for byte in data:
        if byte == 0:
            encoded = '1' + encoded
        else:
            break
    return encoded

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate():
    try:
        data = request.json
        input_words = [word.strip().lower() for word in data.get('words', [])]
        address_count = int(data.get('address_count', 20))  # По умолчанию 20 адресов
        
        # Валидация
        if address_count < 1 or address_count > 100:
            return jsonify({'error': 'Количество адресов должно быть от 1 до 100'}), 400
        
        # Проверка на пустые поля
        if len(input_words) != 11 or any(not word for word in input_words):
            return jsonify({'error': 'Необходимо ввести все 11 слов'}), 400
        
        # Валидация слов
        wordlist = mnemo.wordlist
        for i, word in enumerate(input_words):
            if word not in wordlist:
                return jsonify({'error': f'Слово {i+1} "{word}" не найдено в BIP39 словаре'}), 400
        
        # Генерация валидных фраз
        valid_phrases = []
        count = 0
        
        for word in wordlist:
            if count >= 128:
                break
            
            full_phrase = ' '.join(input_words + [word])
            
            if mnemo.check(full_phrase):
                try:
                    # Генерация данных для фразы
                    seed = mnemo.to_seed(full_phrase, passphrase="")
                    master_key = BIP32Key.fromEntropy(seed)
                    
                    # Генерируем несколько адресов для каждого типа
                    legacy_addresses = []
                    segwit_addresses = []
                    native_segwit_addresses = []
                    
                    for addr_index in range(address_count):
                        # Legacy адрес (m/44'/0'/0'/0/addr_index)
                        legacy_key = master_key.ChildKey(44 + 2**31)
                        legacy_key = legacy_key.ChildKey(0 + 2**31)
                        legacy_key = legacy_key.ChildKey(0 + 2**31)
                        legacy_key = legacy_key.ChildKey(0)
                        legacy_key = legacy_key.ChildKey(addr_index)
                        legacy_addresses.append(legacy_key.Address())
                        
                        # SegWit адрес (m/49'/0'/0'/0/addr_index)
                        segwit_key = master_key.ChildKey(49 + 2**31)
                        segwit_key = segwit_key.ChildKey(0 + 2**31)
                        segwit_key = segwit_key.ChildKey(0 + 2**31)
                        segwit_key = segwit_key.ChildKey(0)
                        segwit_key = segwit_key.ChildKey(addr_index)
                        segwit_addresses.append(pubkey_to_p2sh_p2wpkh_address(segwit_key.PublicKey()))
                        
                        # Native SegWit адрес (m/84'/0'/0'/0/addr_index)
                        native_segwit_key = master_key.ChildKey(84 + 2**31)
                        native_segwit_key = native_segwit_key.ChildKey(0 + 2**31)
                        native_segwit_key = native_segwit_key.ChildKey(0 + 2**31)
                        native_segwit_key = native_segwit_key.ChildKey(0)
                        native_segwit_key = native_segwit_key.ChildKey(addr_index)
                        native_segwit_addresses.append(pubkey_to_p2wpkh_address(native_segwit_key.PublicKey()))
                    
                    # Для первого адреса получаем ключи
                    first_legacy_key = master_key.ChildKey(44 + 2**31).ChildKey(0 + 2**31).ChildKey(0 + 2**31).ChildKey(0).ChildKey(0)
                    private_key_wif = first_legacy_key.WalletImportFormat()
                    public_key_hex = first_legacy_key.PublicKey().hex()
                    
                    valid_phrases.append({
                        'number': count + 1,
                        'mnemonic': full_phrase,
                        'word12': word,
                        'addresses_legacy': legacy_addresses,
                        'addresses_segwit': segwit_addresses,
                        'addresses_native_segwit': native_segwit_addresses,
                        'private_key': private_key_wif,
                        'public_key': public_key_hex
                    })
                    
                    count += 1
                except Exception as e:
                    continue
        
        return jsonify({
            'success': True,
            'count': len(valid_phrases),
            'phrases': valid_phrases
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/wordlist')
def get_wordlist():
    """Возвращает список всех BIP39 слов для автодополнения"""
    return jsonify({'words': mnemo.wordlist})

@app.route('/wordlist-download')
def download_wordlist():
    """Скачать список BIP39 слов с номерами в текстовом формате"""
    from flask import Response
    
    content = "BIP39 Список слов (English)\n"
    content += "="*50 + "\n\n"
    
    for i, word in enumerate(mnemo.wordlist, 1):
        content += f"{i:4d}. {word}\n"
    
    return Response(
        content,
        mimetype="text/plain",
        headers={"Content-disposition": "attachment; filename=bip39_wordlist.txt"}
    )

@app.route('/check-addresses', methods=['POST'])
def check_addresses():
    """Проверить адреса в LMDB базе"""
    try:
        data = request.json
        db_path = data.get('db_path', '')
        addresses = data.get('addresses', [])
        
        if not db_path:
            return jsonify({'error': 'Не указан путь к базе данных'}), 400
        
        if not os.path.exists(db_path):
            return jsonify({'error': f'База данных не найдена: {db_path}'}), 400
        
        if not addresses:
            return jsonify({'error': 'Список адресов пуст'}), 400
        
        results = {}
        found_count = 0
        
        try:
            # Открываем LMDB базу для чтения
            env = lmdb.open(db_path, readonly=True, lock=False, max_dbs=0)
            
            with env.begin() as txn:
                for addr in addresses:
                    # Проверяем наличие адреса в базе
                    # Пробуем разные варианты ключа
                    found = False
                    value = None
                    
                    # Вариант 1: адрес как есть
                    key = addr.encode('utf-8')
                    value = txn.get(key)
                    
                    if value is not None:
                        found = True
                    
                    results[addr] = {
                        'found': found,
                        'value': value.decode('utf-8') if value else None
                    }
                    
                    if found:
                        found_count += 1
            
            env.close()
            
            return jsonify({
                'success': True,
                'total': len(addresses),
                'found': found_count,
                'results': results
            })
            
        except lmdb.Error as e:
            return jsonify({'error': f'Ошибка при работе с LMDB: {str(e)}'}), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Bitcoin Seed Phrase Generator")
    print("="*60)
    print("\n📱 Откройте в браузере: http://localhost:5001")
    print("\n⚠️  Нажмите Ctrl+C для остановки сервера\n")
    app.run(debug=False, host='127.0.0.1', port=5001)

