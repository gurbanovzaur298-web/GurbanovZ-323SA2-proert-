import socket
import struct
import time
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
import threading

TIPI_ZAPISEY = {
    1: "A",          # IPv4 адрес
    28: "AAAA",      # IPv6 адрес  
    5: "CNAME",      # Каноническое имя
    15: "MX",        # Почтовый обменник
    2: "NS",         # Сервер имен
    16: "TXT"        # Текстовая запись
}

@dataclass
class DNSZapis:
    imya: str            
    tip: int               
    klass: int             
    ttl: int              
    dannie: any          
    vremya_dobavleniya: float  

class DNSKesh:
    def __init__(self):
        self.kesh: Dict[str, List[DNSZapis]] = {}
        self.zamok = threading.Lock()  
    
    def poluchit(self, domen: str, tip_zaprosa: int) -> Optional[List[DNSZapis]]:
        """Получить записи из кэша по домену и типу"""
        klyuch = f"{domen.lower()}_{tip_zaprosa}"
        
        with self.zamok:
            if klyuch in self.kesh:
                zapisi = self.kesh[klyuch]
                svezhiye_zapisi = []
                
                for zapis in zapisi:
                    vremya_proshlo = time.time() - zapis.vremya_dobavleniya
                    if vremya_proshlo < zapis.ttl:
                        svezhiye_zapisi.append(zapis)
                
                if svezhiye_zapisi:
                    return svezhiye_zapisi
                else:
                    del self.kesh[klyuch]
        
        return None
    
    def dobavit(self, domen: str, tip_zaprosa: int, zapisi: List[DNSZapis]):
        """Добавить записи в кэш"""
        if not zapisi:
            return
        
        klyuch = f"{domen.lower()}_{tip_zaprosa}"
        
        with self.zamok:
            self.kesh[klyuch] = zapisi
    
    def ochistit(self):
        """Очистить весь кэш"""
        with self.zamok:
            self.kesh.clear()
    
    def pokazat_statistiku(self):
        """Показать статистику кэша"""
        with self.zamok:
            if not self.kesh:
                print("Кэш пуст")
                return
                
            print(f"Записей в кэше: {len(self.kesh)}")
            for klyuch, zapisi in self.kesh.items():
                domen, tip = klyuch.split('_')
                tip_name = TIPI_ZAPISEY.get(int(tip), f"Неизвестный({tip})")
                print(f"  {domen} [{tip_name}]: {len(zapisi)} записей")

class DNSResolyver:
    def __init__(self, dns_servers: List[str] = None):
        self.kesh = DNSKesh()
        self.dns_servers = dns_servers or [
            '8.8.8.8',       
            '1.1.1.1',      
            '77.88.8.8',     
            '208.67.222.222'  
        ]
        self.port = 53
        self.timeout = 3.0
        self.id_schetchik = 0
    
    def sozdat_soket(self) -> socket.socket:
        """Создать UDP сокет для DNS запросов"""
        soket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        soket.settimeout(self.timeout)
        return soket
    
    def zakodirovat_domen(self, domen: str) -> bytes:
        """Кодировать доменное имя в DNS формат"""
        chasti = domen.rstrip('.').split('.')
        zakodirovanniy = b''
        
        for chast in chasti:
            dlina = len(chast)
            if dlina > 63:
                raise ValueError(f"Часть домена слишком длинная: {chast}")
            zakodirovanniy += bytes([dlina]) + chast.encode('ascii', 'ignore')
        
        zakodirovanniy += b'\x00'  # Конец имени
        return zakodirovanniy
    
    def dekodirovat_domen(self, dannie: bytes, start: int) -> Tuple[str, int]:
        """Декодировать доменное имя из DNS пакета"""
        imya_chasti = []
        pozitsiya = start
        
        while dannie[pozitsiya] != 0:
            dlina = dannie[pozitsiya]
            pozitsiya += 1
            
            if dlina & 0xC0 == 0xC0:
                ukazatel = ((dlina & 0x3F) << 8) | dannie[pozitsiya]
                pozitsiya += 1
                chasti, _ = self.dekodirovat_domen(dannie, ukazatel)
                return chasti, pozitsiya
            
            imya_chasti.append(dannie[pozitsiya:pozitsiya+dlina].decode('ascii', 'ignore'))
            pozitsiya += dlina
        
        pozitsiya += 1  # Пропускаем нулевой байт
        return '.'.join(imya_chasti), pozitsiya
    
    def sozdat_zapros(self, domen: str, tip_zaprosa: int) -> bytes:
        """Создать DNS запрос пакет"""
        self.id_schetchik = (self.id_schetchik + 1) % 65536
        id_zaprosa = self.id_schetchik
        
        zagolovok = struct.pack('!HHHHHH',
                              id_zaprosa,     
                              0x0100,         
                              1,            
                              0,              
                              0,         
                              0)              
        
        vopros = self.zakodirovat_domen(domen)
        vopros += struct.pack('!HH', tip_zaprosa, 1)  # Тип и класс (IN = 1)
        
        return zagolovok + vopros
    
    def razobrat_zapis(self, dannie: bytes, start: int) -> Tuple[DNSZapis, int]:
        """Разобрать одну DNS запись из ответа"""
        imya, pozitsiya = self.dekodirovat_domen(dannie, start)
        
        tip, klass, ttl, dlina = struct.unpack('!HHIH', dannie[pozitsiya:pozitsiya+10])
        pozitsiya += 10
        
        dannye_zapisi = dannie[pozitsiya:pozitsiya+dlina]
        
        if tip == 1:  
            if dlina == 4:
                ip = socket.inet_ntoa(dannye_zapisi)
                zapis = DNSZapis(imya, tip, klass, ttl, ip, time.time())
        
        elif tip == 28: 
            if dlina == 16:
                try:
                    ip = socket.inet_ntop(socket.AF_INET6, dannye_zapisi)
                    zapis = DNSZapis(imya, tip, klass, ttl, ip, time.time())
                except:
                    zapis = DNSZapis(imya, tip, klass, ttl, "Ошибка IPv6", time.time())
        
        elif tip == 5: 
            cname, _ = self.dekodirovat_domen(dannie, pozitsiya)
            zapis = DNSZapis(imya, tip, klass, ttl, cname, time.time())
        
        elif tip == 15:
            if dlina >= 2:
                prioritet = struct.unpack('!H', dannye_zapisi[:2])[0]
                server, _ = self.dekodirovat_domen(dannie, pozitsiya + 2)
                zapis = DNSZapis(imya, tip, klass, ttl, f"{prioritet} {server}", time.time())
        
        elif tip == 2: 
            ns_server, _ = self.dekodirovat_domen(dannie, pozitsiya)
            zapis = DNSZapis(imya, tip, klass, ttl, ns_server, time.time())
        
        elif tip == 16: 
            try:
                txt = dannye_zapisi[1:].decode('utf-8', 'ignore')  
                zapis = DNSZapis(imya, tip, klass, ttl, txt, time.time())
            except:
                zapis = DNSZapis(imya, tip, klass, ttl, "Бинарные данные", time.time())
        
        else:
            # Неизвестный тип записи
            zapis = DNSZapis(imya, tip, klass, ttl, dannye_zapisi.hex(), time.time())
        
        pozitsiya += dlina
        return zapis, pozitsiya
    
    def otpravit_zapros(self, domen: str, tip_zaprosa: int = 1) -> List[DNSZapis]:
        """Отправить DNS запрос и получить ответ"""
        iz_kesha = self.kesh.poluchit(domen, tip_zaprosa)
        if iz_kesha:
            return iz_kesha
        
        paket_zaprosa = self.sozdat_zapros(domen, tip_zaprosa)
        
        for dns_server in self.dns_servers:
            try:
                soket = self.sozdat_soket()
                
                soket.sendto(paket_zaprosa, (dns_server, self.port))
                
                paket_otveta, _ = soket.recvfrom(1024)
                soket.close()
                
                if not paket_otveta:
                    continue
                
                otvety = self.razobrat_otvet(paket_otveta, tip_zaprosa)
                
                if otvety:
                    self.kesh.dobavit(domen, tip_zaprosa, otvety)
                    return otvety
            
            except socket.timeout:
                continue
            except Exception as e:
                print(f"Ошибка при запросе к {dns_server}: {e}")
                continue
        
        return []
    
    def razobrat_otvet(self, paket: bytes, iskomy_tip: int) -> List[DNSZapis]:
        """Разобрать весь DNS ответ"""
        otvety = []
        
        try:
            id_z, flagi, voprosi, otveti, auth, dop = struct.unpack('!HHHHHH', paket[:12])
            
            if not (flagi & 0x8000):
                return []
            
            kod_oshibki = flagi & 0x000F
            if kod_oshibki != 0:
                oshibki_dns = {
                    0: "Нет ошибки",
                    1: "Ошибка формата запроса",
                    2: "Ошибка сервера",
                    3: "Домен не найден",
                    4: "Функция не реализована",
                    5: "Запрос отклонён"
                }
                print(f"DNS ошибка: {oshibki_dns.get(kod_oshibki, f'Неизвестная ошибка {kod_oshibki}')}")
                return []
            
            pozitsiya = 12
            
            for _ in range(voprosi):
                _, pozitsiya = self.dekodirovat_domen(paket, pozitsiya)
                pozitsiya += 4  # Тип и класс
            
            for _ in range(otveti):
                zapis, pozitsiya = self.razobrat_zapis(paket, pozitsiya)
                otvety.append(zapis)
        
        except Exception as e:
            print(f"Ошибка при разборе ответа: {e}")
        
        return otvety
      
    def nayti_ipv4(self, domen: str) -> List[str]:
        """Найти IPv4 адреса (A записи)"""
        zapisi = self.otpravit_zapros(domen, 1)
        return [z.dannie for z in zapisi if z.tip == 1]
    
    def nayti_ipv6(self, domen: str) -> List[str]:
        """Найти IPv6 адреса (AAAA записи)"""
        zapisi = self.otpravit_zapros(domen, 28)
        return [z.dannie for z in zapisi if z.tip == 28]
    
    def nayti_cname(self, domen: str) -> List[str]:
        """Найти CNAME записи"""
        zapisi = self.otpravit_zapros(domen, 5)
        return [z.dannie for z in zapisi if z.tip == 5]
    
    def nayti_mx(self, domen: str) -> List[str]:
        """Найти MX записи (почтовые серверы)"""
        zapisi = self.otpravit_zapros(domen, 15)
        return [z.dannie for z in zapisi if z.tip == 15]
    
    def nayti_ns(self, domen: str) -> List[str]:
        """Найти NS записи (серверы имен)"""
        zapisi = self.otpravit_zapros(domen, 2)
        return [z.dannie for z in zapisi if z.tip == 2]
    
    def pokazat_vse_dlya_domena(self, domen: str):
        """Показать все DNS записи для домена"""
        print(f"\n{'='*60}")
        print(f"DNS ЗАПИСИ ДЛЯ: {domen}")
        print(f"{'='*60}")
        
        if not self._vyglyadit_kak_domen(domen):
            print(f"\n'{domen}' не похоже на доменное имя.")
            print("Примеры правильных доменов: google.com, yandex.ru, github.com")
            return
        
        found_anything = False
        
        print("\nA записи (IPv4):")
        a_zapisi = self.nayti_ipv4(domen)
        if a_zapisi:
            found_anything = True
            for ip in a_zapisi:
                print(f"  → {ip}")
        else:
            print("  Не найдено")
        
        print("\nAAAA записи (IPv6):")
        aaaa_zapisi = self.nayti_ipv6(domen)
        if aaaa_zapisi:
            found_anything = True
            for ip in aaaa_zapisi:
                print(f"  → {ip}")
        else:
            print("  Не найдено")
        
        print("\nCNAME записи:")
        cname_zapisi = self.nayti_cname(domen)
        if cname_zapisi:
            found_anything = True
            for cname in cname_zapisi:
                print(f"  → {cname}")
        else:
            print("  Не найдено")
        
        print("\nMX записи (почтовые серверы):")
        mx_zapisi = self.nayti_mx(domen)
        if mx_zapisi:
            found_anything = True
            for mx in mx_zapisi:
                print(f"  → {mx}")
        else:
            print("  Не найдено")
        
        print("\nNS записи (серверы имен):")
        ns_zapisi = self.nayti_ns(domen)
        if ns_zapisi:
            found_anything = True
            for ns in ns_zapisi:
                print(f"  → {ns}")
        else:
            print("  Не найдено")
        
        if not found_anything:
            print(f"\n⚠️ Не удалось найти DNS записи для '{domen}'")
            print("Возможные причины:")
            print("  • Домен не существует")
            print("  • Проблемы с интернет-соединением")
            print("  • DNS серверы временно недоступны")
    
    def _vyglyadit_kak_domen(self, text: str) -> bool:
        """Проверить, похож ли текст на доменное имя"""
        if '.' not in text:
            return False
        
        import re
        pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]$'
        return bool(re.match(pattern, text))

def interaktivniy_rezhim():
    """Интерактивный режим работы с DNS резолвером"""
    resolver = DNSResolyver()
    
    print("DNS РЕЗОЛВЕР - ИНТЕРАКТИВНЫЙ РЕЖИМ")
    print("=" * 60)
    print("КАК ПОЛЬЗОВАТЬСЯ:")
    print("  Просто введите доменное имя, например: google.com")
    print("\nСПЕЦИАЛЬНЫЕ КОМАНДЫ:")
    print("  help     - показать эту справку")
    print("  cache    - показать статистику кэша")
    print("  clear    - очистить кэш")
    print("  exit     - завершить работу")
    print("=" * 60)
    print("Примеры доменов для теста: google.com, yandex.ru, github.com")
    print("=" * 60)
    
    while True:
        try:
            vvod = input("\nВведите домен или команду: ").strip()
            
            if not vvod:
                continue
            
            vvod_lower = vvod.lower()
            
            if vvod_lower == 'exit' or vvod_lower == 'выход':
                print("Завершение работы...")
                break
            
            elif vvod_lower == 'help' or vvod_lower == 'помощь':
                print("\nСПРАВКА:")
                print("  Просто введите домен (например: google.com)")
                print("  Или используйте команды: help, cache, clear, exit")
            
            elif vvod_lower == 'cache' or vvod_lower == 'кэш':
                resolver.kesh.pokazat_statistiku()
            
            elif vvod_lower == 'clear' or vvod_lower == 'очистка':
                resolver.kesh.ochistit()
                print("Кэш очищен!")
            
            else:
                domen = vvod
                resolver.pokazat_vse_dlya_domena(domen)
        
        except KeyboardInterrupt:
            print("\n\nЗавершение работы...")
            break
        except Exception as e:
            print(f"❌ Ошибка: {e}")

def main():
    """Главная функция программы"""
    print("DNS РЕЗОЛВЕР НА PYTHON")
    print("=" * 60)
    
    while True:
        print("\nВЫБЕРИТЕ РЕЖИМ РАБОТЫ:")
        print("  1 - Интерактивный режим ")
        print("  2 - Быстрый тест популярных доменов")
        print("  3 - Выход")
        
        vybor = input("\nВаш выбор (1-3): ").strip()
        
        if vybor == '1':
            interaktivniy_rezhim()
            break  
        
        elif vybor == '2':
            print("\n" + "="*60)
            print("БЫСТРЫЙ ТЕСТ POPULARНЫХ ДОМЕНОВ")
            print("="*60)
            
            resolver = DNSResolyver()
            test_domeny = ["google.com", "yandex.ru", "github.com"]
            
            for domen in test_domeny:
                print(f"\n📡 Запрос {domen}...")
                a_zapisi = resolver.nayti_ipv4(domen)
                if a_zapisi:
                    print(f"   IPv4 адреса: {', '.join(a_zapisi)}")
                else:
                    print(f"   ❌ Не удалось найти IP адреса")
                
                time.sleep(0.5)
            
            print("\n" + "="*60)
            print("Тест завершен!")
            continue
        
        elif vybor == '3':
            print("Выход из программы")
            break
        
        else:
            print(" Неверный выбор. Пожалуйста, введите 1, 2 или 3")

if __name__ == "__main__":
   main()