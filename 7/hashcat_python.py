#!/usr/bin/env python3
"""Quebra de hash por mascara, em Python, para fins didaticos.

Este programa implementa o principio usado em um ataque de mascara: gera cada
senha candidata, calcula seu hash e o compara com o hash procurado. Ele nao e
uma reimplementacao completa do Hashcat e nao utiliza aceleracao por GPU.

Mascaras aceitas:
    ?l  letras minusculas
    ?u  letras maiusculas
    ?d  digitos
    ?s  simbolos ASCII
    ?a  letras, digitos e simbolos ASCII
    ??  caractere de interrogacao literal

Exemplo de uso (nao executado automaticamente):
    python hashcat_python.py key_for_rsa_public.hash "pe?l?l?d"
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import string
import sys
import time
from pathlib import Path
from typing import Iterator, Sequence


CHARSETS = {
    "l": string.ascii_lowercase,
    "u": string.ascii_uppercase,
    "d": string.digits,
    "s": string.punctuation,
}
CHARSETS["a"] = (
    CHARSETS["l"] + CHARSETS["u"] + CHARSETS["d"] + CHARSETS["s"]
)
SUPPORTED_ALGORITHMS = (
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "blake2b",
    "blake2s",
)


def parse_mask(mask: str) -> list[str]:
    """Converte uma mascara em uma lista de conjuntos para cada posicao."""
    positions: list[str] = []
    index = 0

    while index < len(mask):
        character = mask[index]

        if character != "?":
            positions.append(character)
            index += 1
            continue

        if index + 1 >= len(mask):
            raise ValueError("A mascara termina com '?' sem um especificador.")

        code = mask[index + 1]
        if code == "?":
            positions.append("?")
        elif code in CHARSETS:
            positions.append(CHARSETS[code])
        else:
            valid_codes = ", ".join(f"?{item}" for item in (*CHARSETS, "?"))
            raise ValueError(
                f"Especificador '?{code}' desconhecido. Use: {valid_codes}."
            )

        index += 2

    if not positions:
        raise ValueError("A mascara nao pode ser vazia.")

    return positions


def candidates(positions: Sequence[str]) -> Iterator[str]:
    """Gera candidatos sem manter todo o espaco de busca na memoria."""
    for combination in itertools.product(*positions):
        yield "".join(combination)


def search_hash(
    target_hash: str,
    mask: str,
    algorithm: str,
    encoding: str,
    progress_interval: int,
    runtime: float,
) -> tuple[str | None, int, float, bool]:
    """Procura uma entrada cujo hash hexadecimal seja igual ao hash alvo."""
    positions = parse_mask(mask)
    normalized_target = target_hash.strip().lower()
    expected_length = hashlib.new(algorithm).digest_size * 2

    if len(normalized_target) != expected_length:
        raise ValueError(
            f"O hash informado tem {len(normalized_target)} caracteres; "
            f"{algorithm} em hexadecimal exige {expected_length}."
        )

    try:
        bytes.fromhex(normalized_target)
    except ValueError as error:
        raise ValueError("O hash deve estar em formato hexadecimal.") from error

    total = 1
    for charset in positions:
        total *= len(charset)

    started_at = time.perf_counter()

    for attempts, candidate in enumerate(candidates(positions), start=1):
        digest = hashlib.new(algorithm, candidate.encode(encoding)).hexdigest()

        if digest == normalized_target:
            elapsed = time.perf_counter() - started_at
            return candidate, attempts, elapsed, False

        if runtime > 0 and attempts % 10_000 == 0:
            elapsed = time.perf_counter() - started_at
            if elapsed >= runtime:
                return None, attempts, elapsed, True

        if progress_interval > 0 and attempts % progress_interval == 0:
            elapsed = time.perf_counter() - started_at
            rate = attempts / elapsed if elapsed else 0.0
            percentage = attempts / total * 100
            print(
                f"Progresso: {attempts:,}/{total:,} "
                f"({percentage:.2f}%) - {rate:,.0f} tentativas/s",
                file=sys.stderr,
            )

    elapsed = time.perf_counter() - started_at
    return None, total, elapsed, False


def read_target_hash(path: Path) -> str:
    """Le o primeiro valor nao vazio do arquivo de hash."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ValueError(f"Nao foi possivel ler '{path}': {error}") from error

    for line in lines:
        value = line.strip()
        if value:
            return value

    raise ValueError(f"O arquivo '{path}' nao contem um hash.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Procura uma senha por mascara e comparacao de hashes."
    )
    parser.add_argument("hash_file", type=Path, help="arquivo com o hash hexadecimal")
    parser.add_argument("mask", help="mascara, por exemplo: pe?l?l?d")
    parser.add_argument(
        "--algorithm",
        default="sha256",
        choices=SUPPORTED_ALGORITHMS,
        help="algoritmo de hash (padrao: sha256)",
    )
    parser.add_argument(
        "--encoding",
        default="utf-8",
        help="codificacao dos candidatos (padrao: utf-8)",
    )
    parser.add_argument(
        "--progress-interval",
        type=int,
        default=100_000,
        metavar="N",
        help="exibe progresso a cada N tentativas; use 0 para desativar",
    )
    parser.add_argument(
        "--runtime",
        type=float,
        default=0,
        metavar="SEGUNDOS",
        help="interrompe a busca apos o tempo indicado; 0 significa sem limite",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.progress_interval < 0:
        print("Erro: --progress-interval nao pode ser negativo.", file=sys.stderr)
        return 2
    if args.runtime < 0:
        print("Erro: --runtime nao pode ser negativo.", file=sys.stderr)
        return 2

    try:
        target_hash = read_target_hash(args.hash_file)
        password, attempts, elapsed, timed_out = search_hash(
            target_hash=target_hash,
            mask=args.mask,
            algorithm=args.algorithm,
            encoding=args.encoding,
            progress_interval=args.progress_interval,
            runtime=args.runtime,
        )
    except (LookupError, UnicodeError, ValueError) as error:
        print(f"Erro: {error}", file=sys.stderr)
        return 2

    rate = attempts / elapsed if elapsed else 0.0

    if password is not None:
        print("Status: Cracked")
        print(f"Senha: {password}")
        print(f"Tentativas: {attempts:,}")
        print(f"Tempo: {elapsed:.3f} s")
        print(f"Velocidade: {rate:,.0f} tentativas/s")
        return 0

    if timed_out:
        print("Status: Timeout")
        print(f"Tentativas: {attempts:,}")
        print(f"Tempo: {elapsed:.3f} s")
        print(f"Velocidade: {rate:,.0f} tentativas/s")
        return 3

    print("Status: Exhausted")
    print(f"Tentativas: {attempts:,}")
    print(f"Tempo: {elapsed:.3f} s")
    print(f"Velocidade: {rate:,.0f} tentativas/s")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
