from flask import Flask, render_template, request, jsonify
from mnemonic import Mnemonic
from bip32utils import BIP32Key
import hashlib
import bech32

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
                    
                    # Legacy адрес (m/44'/0'/0'/0/0)
                    legacy_key = master_key.ChildKey(44 + 2**31)
                    legacy_key = legacy_key.ChildKey(0 + 2**31)
                    legacy_key = legacy_key.ChildKey(0 + 2**31)
                    legacy_key = legacy_key.ChildKey(0)
                    legacy_key = legacy_key.ChildKey(0)
                    
                    legacy_address = legacy_key.Address()
                    private_key_wif = legacy_key.WalletImportFormat()
                    public_key_bytes = legacy_key.PublicKey()
                    public_key_hex = public_key_bytes.hex()
                    
                    # SegWit адрес (m/49'/0'/0'/0/0) - начинается с 3
                    segwit_key = master_key.ChildKey(49 + 2**31)
                    segwit_key = segwit_key.ChildKey(0 + 2**31)
                    segwit_key = segwit_key.ChildKey(0 + 2**31)
                    segwit_key = segwit_key.ChildKey(0)
                    segwit_key = segwit_key.ChildKey(0)
                    segwit_address = pubkey_to_p2sh_p2wpkh_address(segwit_key.PublicKey())
                    
                    # Native SegWit адрес (m/84'/0'/0'/0/0) - начинается с bc1
                    native_segwit_key = master_key.ChildKey(84 + 2**31)
                    native_segwit_key = native_segwit_key.ChildKey(0 + 2**31)
                    native_segwit_key = native_segwit_key.ChildKey(0 + 2**31)
                    native_segwit_key = native_segwit_key.ChildKey(0)
                    native_segwit_key = native_segwit_key.ChildKey(0)
                    native_segwit_address = pubkey_to_p2wpkh_address(native_segwit_key.PublicKey())
                    
                    valid_phrases.append({
                        'number': count + 1,
                        'mnemonic': full_phrase,
                        'word12': word,
                        'address_legacy': legacy_address,
                        'address_segwit': segwit_address,
                        'address_native_segwit': native_segwit_address,
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

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 Bitcoin Seed Phrase Generator")
    print("="*60)
    print("\n📱 Откройте в браузере: http://localhost:5001")
    print("\n⚠️  Нажмите Ctrl+C для остановки сервера\n")
    app.run(debug=False, host='127.0.0.1', port=5001)

