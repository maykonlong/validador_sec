import hashlib
import itertools
import string
import time
from typing import Dict, Any

class HashCracker:
    """Quebrador híbrido: Wordlist + Bruteforce Incremental (CPU Bound)"""

    WORDLIST = [
        "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567", "dragon",
        "admin", "admin123", "secret", "server", "root", "toor", "changeme", "login", "pass", "hello",
        "default", "manager", "guest", "test", "network", "cisco", "password123", "letmein", "master", "access",
        "security", "welcome", "system", "webmaster", "database", "1234567890", "123123", "iphone", "google",
        "hunter2", "soccer", "football", "baseball", "iloveyou", "princess", "rockyou",
        "Test@123", "Admin#2024", "Abc$1234", "Pass!123", "Secure*99"
    ]

    def crack(self, hash_str: str, workers: int = 1) -> Dict[str, Any]:
        """Tenta quebrar o hash usando múltiplos métodos"""
        start_time = time.time()
        self._cracked_pass = None
        
        result = {
            'hash': hash_str,
            'type': 'Desconhecido',
            'cracked': False,
            'password': None,
            'method': None,
            'time_taken': 0
        }

        clean_hash = hash_str.strip().lower()

        # 1. Identificar Candidatos de Algoritmo
        candidates = self._identify_algo_candidates(clean_hash)
        if not candidates:
            result['error'] = 'Formato de hash desconhecido ou tamanho inválido.'
            return result
        
        # Se houver mais de um candidato, lista todos no tipo (ex: SHA512/Blake)
        result['type'] = "/".join([c[0] for c in candidates])

        # Iterar sobre algoritmos candidatos (em caso de colisão de tamanho, testa todos)
        for algo_name, algo_func in candidates:
            # 2. Ataque 1: Wordlist Rápida
            if self._check_list(self.WORDLIST, clean_hash, algo_func):
                result['type'] = algo_name # Confirmed
                return self._build_success(result, "Wordlist Interna (Comum)", start_time)

            # 3. Ataque 2: Bruteforce Numérico (PINs)
            if self._bruteforce_pins(clean_hash, algo_func, 6):
                result['type'] = algo_name # Confirmed
                return self._build_success(result, "Bruteforce Numérico (PIN)", start_time)

            # 4. Ataque 3: Bruteforce Short
            if self._bruteforce_alpha(clean_hash, algo_func, 4):
                 result['type'] = algo_name # Confirmed
                 return self._build_success(result, "Bruteforce Incremental (Curta)", start_time)

            # 5. Ataque 4: Bruteforce Datas (Smart)
            # Testa todas as datas de 1940 a 2025 (ddmmyy, ddmmyyyy, etc)
            if self._bruteforce_dates(clean_hash, algo_func):
                result['type'] = algo_name # Confirmed
                return self._build_success(result, "Bruteforce Datas (Smart)", start_time)

        # Falha
        result['time_taken'] = round(time.time() - start_time, 2)
        result['analysis'] = f"Falha após força bruta em {result['type']}. Senha complexa."
        return result

    def _identify_algo_candidates(self, h):
        """Retorna lista de (Nome, Função) baseada no tamanho do hash"""
        l = len(h)
        candidates = []
        
        if l == 32: 
            candidates.append(('MD5', hashlib.md5))
        elif l == 40: 
            candidates.append(('SHA1', hashlib.sha1))
        elif l == 56:
            candidates.append(('SHA224', hashlib.sha224))
            # SHA3-224 também tem 56 bytes hex? Não, hashlib.sha3_224
            if hasattr(hashlib, 'sha3_224'): candidates.append(('SHA3-224', hashlib.sha3_224))
        elif l == 64:
            candidates.append(('SHA256', hashlib.sha256))
            if hasattr(hashlib, 'sha3_256'): candidates.append(('SHA3-256', hashlib.sha3_256))
            if hasattr(hashlib, 'blake2s'): candidates.append(('BLAKE2s', hashlib.blake2s))
        elif l == 96:
            candidates.append(('SHA384', hashlib.sha384))
            if hasattr(hashlib, 'sha3_384'): candidates.append(('SHA3-384', hashlib.sha3_384))
        elif l == 128:
            candidates.append(('SHA512', hashlib.sha512))
            if hasattr(hashlib, 'sha3_512'): candidates.append(('SHA3-512', hashlib.sha3_512))
            if hasattr(hashlib, 'blake2b'): candidates.append(('BLAKE2b', hashlib.blake2b))
            
        return candidates

    def _build_success(self, res, method, start):
        res['cracked'] = True
        res['password'] = self._cracked_pass
        res['method'] = method
        res['time_taken'] = round(time.time() - start, 4)
        res['complexity'] = f"Quebrada via {method}"
        return res

    def yield_passwords(self):
        """Iterador mestre que gera todas as senhas (Wordlist+Rules, PINs, Datas, Short)"""
        
        # 1. Wordlist + Rules
        for base_word in self.WORDLIST:
            for word in self._mutate(base_word):
                yield word
        
        # 2. Bruteforce PINs (0-999999)
        # Otimizado: gera strings
        for i in range(1000000):
            s = str(i)
            yield s
            if len(s) < 6:
                yield s.zfill(6)
                yield s.zfill(4)

        # 3. Dates (1940-2025)
        for year in range(1940, 2026):
            sy = str(year)
            yield sy # 1980
            yield sy[2:] # 80
            
            for m in range(1, 13):
                sm = f"{m:02d}"
                max_d = 31 # Simplificação rápida para speed
                for d in range(1, max_d + 1):
                    sd = f"{d:02d}"
                    # Patterns
                    yield f"{sd}{sm}{sy}"      # 25121980
                    yield f"{sd}{sm}{sy[2:]}"  # 251280
                    yield f"{sy}{sm}{sd}"      # 19801225
                    yield f"{sd}/{sm}/{sy}"    # 25/12/1980

        # 4. Short Alpha (1-4 chars)
        chars = string.ascii_lowercase + string.digits
        for length in range(1, 5):
            for attempt in itertools.product(chars, repeat=length):
                yield "".join(attempt)

    def _check_list(self, lst, target_hash, algo):
        """Verifica wordlist com aplicação de regras de mutação (Rule-Based)"""
        # Nota: Usamos apenas a lista fornecida aqui, não o yield_passwords completo
        # para manter a granularidade do report (saber se foi wordlist ou bruteforce)
        for base_word in lst:
            for word in self._mutate(base_word):
                if algo(word.encode()).hexdigest() == target_hash:
                    self._cracked_pass = word
                    return True
        return False

    def _mutate(self, word):
        """Gera variações inteligentes da palavra (Rule-based attack)"""
        # 1. Base
        yield word
        
        # 2. Case Variations
        yield word.capitalize() # Admin
        yield word.upper()      # ADMIN
        yield word.lower()      # admin
        
        # 3. Common Appends (Anos, sequencias)
        suffixes = ["123", "1234", "12345", "1", "!", "*", "@", "#", "2023", "2024", "2025", "01", "007"]
        for suffix in suffixes:
            yield f"{word}{suffix}"
            yield f"{word.capitalize()}{suffix}" # Admin123
            
        # 4. Common Prepends
        prefixes = ["!", "#", "@", "_"]
        for prefix in prefixes:
             yield f"{prefix}{word}"
        
        # 5. Leet Speak Simples (a->@, e->3, o->0, i->1, s->$)
        leet = word
        changes = 0
        if 'a' in leet: 
            leet = leet.replace('a', '@')
            changes += 1
        if 'e' in leet: 
            leet = leet.replace('e', '3')
            changes += 1
        if 'o' in leet: 
            leet = leet.replace('o', '0')
            changes += 1
        if 'i' in leet: 
            leet = leet.replace('i', '1')
            changes += 1
        if 's' in leet: 
            leet = leet.replace('s', '$')
            changes += 1
            
        if changes > 0:
            yield leet      # p@ssword
            yield leet + "123" # p@ssword123
            yield leet + "!"   # p@ssword!

    def _bruteforce_dates(self, target_hash, algo):
        """Gera datas comuns de nascimento/eventos (1940-2025)"""
        for year in range(1940, 2026):
            s_year = str(year)
            s_short_year = s_year[2:]
            
            # Apenas ano
            if algo(s_year.encode()).hexdigest() == target_hash:
                self._cracked_pass = s_year
                return True

            for month in range(1, 13):
                s_month = f"{month:02d}"
                max_d = 29 if month == 2 else 30 if month in [4,6,9,11] else 31
                
                for day in range(1, max_d + 1):
                    s_day = f"{day:02d}"
                    candidates = [
                        f"{s_day}{s_month}{s_short_year}", # 251280
                        f"{s_day}{s_month}{s_year}",       # 25121980
                        f"{s_year}{s_month}{s_day}",       # 19801225
                        f"{s_day}/{s_month}/{s_year}"      # 25/12/1980
                    ]
                    for date in candidates:
                        if algo(date.encode()).hexdigest() == target_hash:
                            self._cracked_pass = date
                            return True
        return False

    def _bruteforce_pins(self, target_hash, algo, digits):
        # Tenta de 0 a 999...
        limit = 10**digits
        for i in range(limit):
            val = str(i)
            # Tenta '123' e '000123'
            attempts = [val]
            if len(val) < digits:
                attempts.append(val.zfill(digits)) # Zeros à esquerda
                
            for p in attempts:
                if algo(p.encode()).hexdigest() == target_hash:
                    self._cracked_pass = p
                    return True
        return False

    def _bruteforce_alpha(self, target_hash, algo, max_len):
        chars = string.ascii_lowercase + string.digits # a-z0-9
        # Para senhas até 3 caracteres é instantâneo. 4 demora alguns segundos (Python puro).
        for length in range(1, max_len + 1):
            for attempt in itertools.product(chars, repeat=length):
                word = "".join(attempt)
                if algo(word.encode()).hexdigest() == target_hash:
                    self._cracked_pass = word
                    return True
        return False
