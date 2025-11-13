#!/usr/bin/env python3
import socket
import struct
import sys
import argparse
from pathlib import Path
import signal
import time

class SignalHandler:
    def __init__(self):
        self.shutdown_requested = False
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        print(f"\nSeñal {signum} recibida, cerrando...")
        self.shutdown_requested = True

def decode_xor(data, key):
    if not key:
        return data
    
    key_bytes = key.encode('utf-8')
    key_len = len(key_bytes)
    
    decoded = bytearray()
    for i, byte in enumerate(data):
        decoded_byte = byte ^ key_bytes[i % key_len]
        decoded.append(decoded_byte)
    
    return bytes(decoded)

def receive_files(host='0.0.0.0', port=4444, xor_key=None):
    signal_handler = SignalHandler()
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(1)
        # Hacer el socket no bloqueante con timeout
        s.settimeout(1.0)
        
        print(f"Escuchando en {host}:{port}...")
        print("Presiona Ctrl+C para detener el servidor")
        if xor_key:
            print(f"Modo XOR activado - Clave: '{xor_key}'")
        else:
            print("Modo sin decodificacion XOR")
        
        conn = None
        try:
            while not signal_handler.shutdown_requested:
                try:
                    conn, addr = s.accept()
                    conn.settimeout(1.0)  # Timeout para operaciones de recepción
                    
                    print(f"Conexion establecida desde {addr}")
                    
                    while not signal_handler.shutdown_requested:
                        try:
                            header_data = b''
                            while len(header_data) < 40 and not signal_handler.shutdown_requested:
                                try:
                                    chunk = conn.recv(40 - len(header_data))
                                    if not chunk:
                                        break
                                    header_data += chunk
                                except socket.timeout:
                                    continue
                            
                            if not header_data or len(header_data) < 40:
                                break
                                
                            if signal_handler.shutdown_requested:
                                break
                            
                            filename = header_data[:32].decode('utf-8').rstrip('\x00')
                            filesize = struct.unpack('!I', header_data[32:36])[0]
                            checksum = struct.unpack('!I', header_data[36:40])[0]
                            
                            print(f"Recibiendo: {filename} ({filesize} bytes)")
                            
                            filedata = b''
                            while len(filedata) < filesize and not signal_handler.shutdown_requested:
                                try:
                                    chunk = conn.recv(min(4096, filesize - len(filedata)))
                                    if not chunk:
                                        break
                                    filedata += chunk
                                except socket.timeout:
                                    continue
                            
                            if signal_handler.shutdown_requested:
                                print("Recepción interrumpida por el usuario")
                                break
                            
                            if xor_key and filedata:
                                original_size = len(filedata)
                                filedata = decode_xor(filedata, xor_key)
                                print(f"  XOR aplicado: {original_size} bytes decodificados")
                            
                            output_filename = f"{filename}"
                            
                            with open(output_filename, "wb") as f:
                                f.write(filedata)
                            
                            file_size = Path(output_filename).stat().st_size
                            print(f"Guardado: {output_filename} ({file_size} bytes)")
                            
                        except Exception as e:
                            print(f"Error procesando archivo: {e}")
                            break
                    
                    if conn:
                        conn.close()
                        conn = None
                        
                except socket.timeout:
                    # Timeout en accept, verificar si hay que cerrar
                    continue
                except Exception as e:
                    print(f"Error en aceptar conexión: {e}")
                    if conn:
                        conn.close()
                        conn = None
                    continue
                        
        except Exception as e:
            if not signal_handler.shutdown_requested:
                print(f"Error: {e}")
        
        finally:
            if conn:
                conn.close()
            print("Servidor cerrado correctamente")

def main():
    parser = argparse.ArgumentParser(description='Recibir archivos con opcion de decodificacion XOR')
    parser.add_argument('--host', default='0.0.0.0', help='Direccion IP para escuchar (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=4444, help='Puerto para escuchar (default: 4444)')
    parser.add_argument('--xor-key', help='Clave para decodificacion XOR (opcional)')
    
    args = parser.parse_args()
    
    print("=== RECEPTOR DE ARCHIVOS ===")
    print(f"Host: {args.host}")
    print(f"Port: {args.port}")
    
    if args.xor_key:
        print(f"Clave XOR: {args.xor_key}")
        print("Modo: Con decodificacion XOR")
    else:
        print("Modo: Sin decodificacion")
    
    print("=" * 30)
    
    try:
        receive_files(args.host, args.port, args.xor_key)
    except Exception as e:
        print(f"Error fatal: {e}")

if __name__ == "__main__":
    main()