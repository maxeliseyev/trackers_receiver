#!/usr/bin/env python3
import socket
import struct
import time

# Минимальный валидный EGTS пакет (APPDATA с одной пустой записью)
def create_minimal_egts_packet():
    # Transport Layer Header (11 bytes)
    prv = 0x01          # Protocol Version
    skid = 0x00         # Security Key ID
    prefix_flags = 0x00  # No prefix, no encryption, no compression
    hl = 0x0B           # Header Length = 11 bytes
    he = 0x00           # Header Encoding
    fdl = 0x00, 0x00    # Frame Data Length (will be updated)
    pid = 0x01, 0x00    # Packet ID = 1
    pt = 0x01           # Packet Type = APPDATA

    # Service Frame with one minimal record (20 bytes)
    # Record Header
    rl = 0x0F, 0x00     # Record Length = 15 bytes
    rn = 0x00, 0x00     # Record Number = 0
    rfl = 0x00          # Record Flags (no OID, no EVID, no TM)

    # Record Data - одна подзапись SR_POS_DATA (минимальная)
    # Subrecord Header
    srt = 0x10          # SR_POS_DATA = 16
    srl = 0x15, 0x00    # Subrecord Length = 21 bytes

    # SR_POS_DATA минимальные данные (21 byte)
    nav_time = struct.pack('<I', int(time.time()))  # 4 bytes
    lat = struct.pack('<I', 0x66666666)              # 4 bytes ~55.6 градусов
    lon = struct.pack('<I', 0x4CCCCCCD)              # 4 bytes ~37.4 градуса
    flags = 0xE1        # ALTE=1, LOHS=1, LAHS=1, MV=1, BB=0, CS=0, FIX=1, VLD=1
    speed = 0x00, 0x00  # 0 km/h
    course = 0xB3       # 179 degrees
    odometer = 0x00, 0x00, 0x00  # 0 meters
    din = 0x00          # Digital inputs
    src = 0x00          # Source
    alt = 0x00, 0x00, 0x00  # Altitude

    # SST and RST
    sst = 0x02          # EGTS_TELEDATA_SERVICE
    rst = 0x02          # EGTS_TELEDATA_SERVICE

    # Собираем subrecord
    subrecord = bytes([srt]) + bytes(srl) + nav_time + lat + lon + bytes([flags]) + bytes(speed) + bytes([course]) + bytes(odometer) + bytes([din, src]) + bytes(alt)

    # Собираем record
    record = bytes(rl) + bytes(rn) + bytes([rfl, sst, rst]) + subrecord

    # Обновляем FDL
    fdl = struct.pack('<H', len(record))

    # Собираем header
    header = bytes([prv, skid, prefix_flags, hl, he]) + fdl + bytes(pid) + bytes([pt])

    # Вычисляем HCS (CRC8 для заголовка)
    def crc8(data):
        crc = 0xFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x80:
                    crc = (crc << 1) ^ 0x31
                else:
                    crc <<= 1
                crc &= 0xFF
        return crc

    hcs = crc8(header)
    header += bytes([hcs])

    # Вычисляем CRC16 для record
    def crc16(data):
        crc = 0xFFFF
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0x8005
                else:
                    crc >>= 1
        return crc

    crc = crc16(record)

    # Полный пакет
    packet = header + record + struct.pack('<H', crc)

    return packet

# Отправка пакета
def send_packet():
    packet = create_minimal_egts_packet()
    print(f"Created packet: {len(packet)} bytes")
    print(f"First 20 bytes: {packet[:20].hex()}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', 36000))
        print("Connected to server")

        sock.sendall(packet)
        print(f"Sent {len(packet)} bytes")

        # Ждем ответ
        sock.settimeout(5.0)
        try:
            response = sock.recv(1024)
            print(f"Received response: {len(response)} bytes")
            print(f"Response hex: {response.hex()}")
        except socket.timeout:
            print("No response (timeout)")

        sock.close()
        print("Connection closed")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    send_packet()
