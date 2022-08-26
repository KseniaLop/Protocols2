import argparse
from functools import reduce
import socket
import glob
import json
import datetime


def get_question_domain(data):
    state = 0
    expected_length = 0
    domain_string = ''
    domain_parts = []
    x = 0
    y = 0

    for byte in data:
        if state == 1:
            if byte != 0:
                domain_string += chr(byte)
            x += 1
            if x == expected_length:
                domain_parts.append(domain_string)
                domain_string = ''
                state = 0
                x = 0
            if byte == 0:
                domain_parts.append(domain_string)
                break
        else:
            state = 1
            expected_length = byte
        y += 1

    question_type = data[y: y + 2]
    return domain_parts, question_type


def make_type_from_number(type):
    if type == 1:
        return 'a'
    elif type == 2:
        return 'ns'


def get_bit_in_byte(byte, position):
    return str(ord(byte) & (1 << position))


def parse_incoming_request(data):
    header = parse_header(data)
    domain_parts, question_type = get_question_domain(data[12:])
    domain = '.'.join(domain_parts)
    type_number = int.from_bytes(question_type, 'big')
    parsed_type = make_type_from_number(type_number)

    question = {
        'QNAME': domain,
        'QTYPE': parsed_type,
        'QCLASS': 'internet'
    }

    return {
        'header': header,
        'question': question
    }


def parse_flags(flags):
    first_byte = flags[:1]
    second_byte = flags[1:2]
    QR = get_bit_in_byte(first_byte, 0)
    OPCODE = ''
    for bit in range(1, 5):
        OPCODE += get_bit_in_byte(first_byte, bit)
    AA = get_bit_in_byte(first_byte, 5)
    TC = get_bit_in_byte(first_byte, 6)
    RD = get_bit_in_byte(first_byte, 7)
    RA = get_bit_in_byte(second_byte, 8)
    Z = '0000'
    RCODE = ''
    for bit in range(4, 8):
        RCODE += get_bit_in_byte(first_byte, bit)

    return {
        'QR': QR,
        'OPCODE': OPCODE,
        'AA': AA,
        'TC': TC,
        'RD': RD,
        'RA': RA,
        'Z': Z,
        'RCODE': RCODE
    }


def parse_header(data):
    return {
        'ID': data[0:2],
        'FLAGS': parse_flags(data[2:4]),
        'QDCOUNT': int.from_bytes(data[4:6], 'big'),
        'ANCOUNT': int.from_bytes(data[6:8], 'big'),
        'NSCOUNT': int.from_bytes(data[8:10], 'big'),
        'ARCOUNT': int.from_bytes(data[10:12], 'big')
    }


def load_records_info():
    json_info = {}
    info_files = glob.glob('cache/*.info')

    for zone in info_files:
        with open(zone) as file:
            data = json.load(file)
            origin = data['origin']
            json_info[origin] = data

    return json_info


def make_info_from_response(data, domain, qtype):
    question = build_question(domain, qtype)
    answer = data[12 + len(question):]

    count = int.from_bytes(data[6:8], 'big')
    records = get_records_from_answer(answer, count)

    origin = '.'.join(domain)
    time = str(datetime.datetime.now())
    cache_data = {'origin': origin, 'time': time, 'data': records, 'ttl': 360}

    INFO_DATA[origin] = cache_data
    save_info_data(cache_data)
    return cache_data


def save_info_data(data):
    with open(f'cache/{data["origin"].rstrip(".")}.info', 'w+') as f:
        json.dump(data, f)


def sum_reducer(iterable, default):
    return reduce(lambda cur, acc: acc + cur, iterable, default)


def make_ipv4_from_bytes(data):
    ipv4 = sum_reducer(map(lambda d: str(d) + '.', data), '').rstrip('.')
    return ipv4


def get_records_from_answer(answer, count):
    ptr = 0
    records = {}

    for _ in range(count):
        record = {}
        rec_type = int.from_bytes(answer[ptr + 2: ptr + 4], 'big')
        ttl = int.from_bytes(answer[ptr + 6:ptr + 10], 'big')
        rd_length = int.from_bytes(answer[ptr + 10: ptr + 12], 'big')

        rd_data = {
            1: lambda: make_ipv4_from_bytes(answer[ptr + 12:ptr + 12 + rd_length]),
            2: lambda: answer[ptr + 12:ptr + 12 + rd_length].hex()
        }[rec_type]()

        ptr += 12 + rd_length
        rec_type = make_type_from_number(rec_type)
        record['ttl'] = ttl
        record['value'] = rd_data

        if rec_type in records:
            records[rec_type].append(record)
        else:
            records[rec_type] = [record]
    return records


def find_data(domain, qtype):
    request = build_request(domain, qtype)
    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        temp_sock.sendto(request, GOOGLE_NS)
        data, _ = temp_sock.recvfrom(512)
    finally:
        temp_sock.close()

    info = make_info_from_response(data, domain, qtype)
    return info


def get_info(domain, info_data, qtype):
    info_name = '.'.join(domain)
    info = None

    if info_name in info_data:
        print(f'{info_name.rstrip(".")}: данные есть в кэше.')
        info = info_data[info_name]

        if qtype in info['data']:
            time = datetime.datetime.fromisoformat(info['time'])
            ttl = info['ttl']
            current_time = datetime.datetime.now()
            if (current_time - time).seconds > ttl:
                print(
                    f'{info_name.rstrip(".")}: данные устарели.')
                return find_data(domain, qtype)
        else:
            print(
                f'Данные по "{qtype}" запросу не найдены.')
            return find_data(domain, qtype)
    else:
        print(
            f'В кэше нет данных по "{info_name.rstrip(".")}".')
        return find_data(domain, qtype)
    return info


def get_records(data):
    domain, question_type = get_question_domain(data)
    QT = ''
    if question_type == b'\x00\x01':
        QT = 'a'
    elif question_type == b'\x00\x0c':
        QT = 'ptr'
    elif question_type == b'\x00\x02':
        QT = 'ns'

    if QT in ['a', 'ns']:
        return get_info(domain, INFO_DATA, QT)['data'][QT], QT, domain

    return None, QT, domain


def build_question(domain, rec_type):
    question = b''

    for part in domain:
        length = len(part)
        question += bytes([length])

        for char in part:
            question += ord(char).to_bytes(1, byteorder='big')

    if rec_type == 'a':
        question += b'\x00\x01'
    elif rec_type == 'ns':
        question += b'\x00\x02'

    question += b'\x00\x01'
    return question


def record_to_bytes(rec_type, ttl, value):
    record = b'\xc0\x0c'

    if rec_type == 'a':
        record += b'\x00\x01'
    elif rec_type == 'ns':
        record += b'\x00\x02'

    record += b'\x00\x01'
    record += int(ttl).to_bytes(4, byteorder='big')

    if rec_type == 'a':
        record += b'\x00\x04'

        for part in value.split('.'):
            record += bytes([int(part)])
    if rec_type == 'ns':
        byte_value = bytes(bytearray.fromhex(value))
        record += b'\x00' + bytes([len(byte_value)])
        record += byte_value
    return record


AA = '1'
TC = '0'
RD = '1'
RA = '1'
Z = '000'
RCODE = '0000'
QR = '1'


def build_response_flags(flags):
    first_byte = flags[:1]

    OPCODE = ''
    for bit in range(1, 5):
        OPCODE += get_bit_in_byte(first_byte, bit)

    first_byte_str = QR + OPCODE + AA + TC + RD
    second_byte_str = RA + Z + RCODE

    return flags_to_bytes(first_byte_str) + flags_to_bytes(second_byte_str)


def flags_to_bytes(*args):
    string = ''
    for arg in args:
        string += arg
    return int(string, 2).to_bytes(1, byteorder='big')


COMMON_ID = b'\xAA\xAA'
COMMON_FLAGS = b'\x01\x00'
COMMON_QDCOUNT = b'\x00\x01'
COMMON_ANCOUNT = b'\x00\x00'
COMMON_NSCOUNT = b'\x00\x00'
COMMON_ARSCOUNT = b'\x00\x00'
COMMON_REQUEST_HEADER = COMMON_ID + COMMON_FLAGS + COMMON_QDCOUNT + COMMON_ANCOUNT + COMMON_NSCOUNT + COMMON_ARSCOUNT


def build_request(domain, qtype):
    return COMMON_REQUEST_HEADER + build_question(domain, qtype)


def build_response(data):
    records_data = get_records(data[12:])

    ID = data[:2]
    FLAGS = build_response_flags(data[2:4])
    ANCOUNT = len(records_data[0]).to_bytes(2, byteorder='big')
    header = (
            ID
            + FLAGS
            + COMMON_QDCOUNT
            + ANCOUNT
            + COMMON_NSCOUNT
            + COMMON_ARSCOUNT
    )

    records, record_type, domain = records_data
    question = build_question(domain, record_type)

    body = sum_reducer(map(lambda record: record_to_bytes(record_type, record['ttl'], record['value']), records), b'')

    print(f'Ответ отправлен.')

    return header + question + body


def make_response(data):
    request_info = parse_incoming_request(data)
    req_type = request_info['question']['QTYPE']

    res = b''
    if req_type in ['a', 'ns']:
        print(f'Новый запрос. Тип: "{req_type.upper()}".')
        res = build_response(data)

    return res


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="DNS caching server")
    parser.parse_args()

    INFO_DATA = load_records_info()
    GOOGLE_NS = '8.8.8.8', 53

    ip = '127.0.0.1'
    port = 53

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ip, port))

    while True:
        data, addr = sock.recvfrom(512)
        response = make_response(data)
        sock.sendto(response, addr)
