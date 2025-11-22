def dec_to_hex_list(numbers):
    """
    Принимает список десятичных чисел (int).
    Возвращает список строк вида: '280 → 0x118'
    """
    result = []
    for num in numbers:
        n = int(num) % 256
        if n < 0:
            result.append(f"{n} → ОШИБКА: отрицательное")
            continue
        
        hex_str = f"0x{n:X}".zfill(4) 
        
        if n <= 255:
            hex_str = f"0x{n:02X}"  # 0x1B
        else:
            hex_str = f"0x{n:X}"    # 0x118
        
        result.append(f"{n} → {hex_str}")
    
    return result



decimal_numbers = [283, 285, 299, 301, 313, 319, 333, 351, 355, 357, 361, 369,
                   375, 379, 391, 395, 397, 415, 419, 425, 433, 445, 451, 463, 471, 477,
                   487, 499, 501, 505]

# Запуск
for line in dec_to_hex_list(decimal_numbers):
    print(line)