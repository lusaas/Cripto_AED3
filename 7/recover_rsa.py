#!/usr/bin/env python3
"""Reconstrói a chave RSA do grupo 7 e recupera a chave da mensagem."""

import math
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parent
P = 2295796704686193901538758441276290741108975069288091220567
Q = 2841813802634779914926926270734337524686850991346453461081


def write_new_private(path: Path, data: bytes) -> None:
    """Cria um arquivo privado sem sobrescrever arquivos existentes."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)


def main() -> None:
    public = serialization.load_pem_public_key((ROOT / "key_public.pem").read_bytes())
    numbers = public.public_numbers()
    if not isinstance(numbers, rsa.RSAPublicNumbers) or P * Q != numbers.n:
        raise ValueError("Os fatores não correspondem à chave pública RSA")

    modulus_order = math.lcm(P - 1, Q - 1)
    d = pow(numbers.e, -1, modulus_order)
    private = rsa.RSAPrivateNumbers(
        p=P, q=Q, d=d, dmp1=d % (P - 1), dmq1=d % (Q - 1),
        iqmp=pow(Q, -1, P), public_numbers=numbers,
    ).private_key()
    if private.public_key().public_numbers() != numbers:
        raise ValueError("A chave privada reconstruída não corresponde à pública")

    ciphertext = bytes.fromhex((ROOT / "key_for_message.en").read_text().strip())
    block_size = (numbers.n.bit_length() + 7) // 8
    if len(ciphertext) != block_size or int.from_bytes(ciphertext, "big") >= numbers.n:
        raise ValueError("O bloco cifrado não corresponde ao módulo RSA")

    block = pow(int.from_bytes(ciphertext, "big"), d, numbers.n).to_bytes(block_size, "big")
    separator = block.find(b"\x00", 2)
    if block[:2] != b"\x00\x02" or separator < 10:
        raise ValueError("O bloco não contém padding PKCS#1 v1.5 válido")
    message_key = private.decrypt(ciphertext, padding.PKCS1v15())
    if message_key != block[separator + 1 :]:
        raise ValueError("A decifragem não corresponde ao bloco RSA validado")

    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    private_path = ROOT / "key_private.pem"
    message_path = ROOT / "key_for_message.txt"
    if private_path.exists() or message_path.exists():
        raise FileExistsError("Um arquivo de saída já existe; nenhuma saída foi sobrescrita")
    write_new_private(private_path, pem)
    write_new_private(message_path, message_key)
    print("Chave privada validada:", private_path)
    print("Chave da mensagem recuperada:", message_key.decode("ascii"))
    print("Chave da mensagem salva em:", message_path)


if __name__ == "__main__":
    main()
