import re
import requests
import hashlib

import time

start_time = time.time()  # Запомнить время начала выполнения


def check_rules(password: str) -> bool:
    # Проверка длины пароля
    if len(password) < 8:
        return False
    # Проверка на наличие букв верхнего регистра
    if not any(char.isupper() for char in password):
        return False
    # Проверка на наличие букв нижнего регистра
    if not any(char.islower() for char in password):
        return False
    # Проверка на наличие цифр
    if not any(char.isdigit() for char in password):
        return False
    # Проверка на наличие специальных символов
    pattern = r'[^a-zA-Z0-9\s]'
    if not re.search(pattern, password):
        return False
    return True


def is_password_pwned(password: str) -> int:
    # Преобразуем пароль в хеш SHA-1
    password_hash = hashlib.sha1(password.encode()).hexdigest().upper()

    # Делим хеш на префикс и суффикс
    prefix, suffix = password_hash[:5], password_hash[5:]

    # Отправляем запрос к Pwned Passwords API
    response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')

    # Проверяем, был ли найден суффикс в ответе
    for line_in_answer in response.text.splitlines():
        stored_suffix, count = line_in_answer.split(':')
        if stored_suffix == suffix:
            return int(count)  # Пароль найден в базе данных (count - кол-во раз)
    return 0  # Пароль не найден в базе данных


if __name__ == '__main__':
    while True:  # Обработчик ввода
        # full_name = input("Введите полный путь к файлу для корректной работы программы: ")
        try:
            with open("test_data.txt", 'r') as file:
                for line in file:
                    if check_rules(line.strip()):
                        # pwned_result = is_password_pwned(line.strip())
                        # if pwned_result > 0:
                        #     print(f"{line.strip()} [Согласно базам данных HIBP данный пароль был скомпрометирован {pwned_result} раз]")
                        # else:
                        #     print(f"{line.strip()} [Согласно базам данных HIBP данный пароль не был скомпрометирован]")
                        print(line.strip())
            break  # Выход из цикла, если файл успешно обработан
        except FileNotFoundError:
            print("Файл не найден: No such file or directory")
    end_time = time.time()  # Запомнить время окончания выполнения
    elapsed_time = end_time - start_time  # Вычислить время выполнения
    print(f"Время выполнения: {elapsed_time} секунд")