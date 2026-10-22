/*
 * Ataque didatico de dicionario com regras para hashes SHA-256.
 *
 * Compilacao (MSYS2 GCC):
 *   gcc -O3 -std=c11 -Wall -Wextra -o dictionary_rules.exe dictionary_rules.c
 *
 * Uso:
 *   dictionary_rules.exe HASH_FILE WORDLIST RULES [PREFIXO]
 *
 * O programa e independente de bibliotecas criptograficas externas. Ele nao e
 * uma reimplementacao do John the Ripper: reproduz somente o principio de um
 * ataque de dicionario com transformacoes declaradas em um arquivo de regras.
 */

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_LINE 512
#define MAX_CANDIDATE 256
#define MAX_RULES 128

typedef struct {
    uint8_t data[64];
    uint32_t data_len;
    uint64_t bit_len;
    uint32_t state[8];
} Sha256Context;

typedef enum {
    RULE_BASE,
    RULE_LOWER_SUFFIX,
    RULE_UPPER_SUFFIX,
    RULE_CAPITALIZE_SUFFIX,
    RULE_LEET_SUFFIX,
    RULE_REVERSE_SUFFIX,
    RULE_APPEND_DIGITS,
    RULE_APPEND_YEARS,
    RULE_APPEND_SYMBOLS,
    RULE_LEET_APPEND_DIGITS,
    RULE_CAPITALIZE_APPEND_DIGITS
} RuleType;

typedef struct {
    RuleType type;
    int first;
    int last;
    char text[128];
} Rule;

typedef struct {
    uint8_t target[32];
    uint64_t attempts;
    int found;
    char password[MAX_CANDIDATE];
} SearchContext;

static const uint32_t SHA256_CONSTANTS[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t rotate_right(uint32_t value, uint32_t count) {
    return (value >> count) | (value << (32U - count));
}

static void sha256_transform(Sha256Context *context, const uint8_t block[64]) {
    uint32_t words[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (int i = 0; i < 16; ++i) {
        int offset = i * 4;
        words[i] = ((uint32_t)block[offset] << 24) |
                   ((uint32_t)block[offset + 1] << 16) |
                   ((uint32_t)block[offset + 2] << 8) |
                   (uint32_t)block[offset + 3];
    }

    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotate_right(words[i - 15], 7) ^
                      rotate_right(words[i - 15], 18) ^ (words[i - 15] >> 3);
        uint32_t s1 = rotate_right(words[i - 2], 17) ^
                      rotate_right(words[i - 2], 19) ^ (words[i - 2] >> 10);
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }

    a = context->state[0]; b = context->state[1];
    c = context->state[2]; d = context->state[3];
    e = context->state[4]; f = context->state[5];
    g = context->state[6]; h = context->state[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t sum1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + sum1 + choice + SHA256_CONSTANTS[i] + words[i];
        uint32_t sum0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = sum0 + majority;

        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    context->state[0] += a; context->state[1] += b;
    context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f;
    context->state[6] += g; context->state[7] += h;
}

static void sha256_init(Sha256Context *context) {
    context->data_len = 0;
    context->bit_len = 0;
    context->state[0] = 0x6a09e667; context->state[1] = 0xbb67ae85;
    context->state[2] = 0x3c6ef372; context->state[3] = 0xa54ff53a;
    context->state[4] = 0x510e527f; context->state[5] = 0x9b05688c;
    context->state[6] = 0x1f83d9ab; context->state[7] = 0x5be0cd19;
}

static void sha256_update(Sha256Context *context, const uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        context->data[context->data_len++] = data[i];
        if (context->data_len == 64) {
            sha256_transform(context, context->data);
            context->bit_len += 512;
            context->data_len = 0;
        }
    }
}

static void sha256_final(Sha256Context *context, uint8_t digest[32]) {
    uint32_t index = context->data_len;
    context->data[index++] = 0x80;

    if (index > 56) {
        while (index < 64) context->data[index++] = 0;
        sha256_transform(context, context->data);
        index = 0;
    }
    while (index < 56) context->data[index++] = 0;

    context->bit_len += (uint64_t)context->data_len * 8;
    for (int i = 0; i < 8; ++i)
        context->data[63 - i] = (uint8_t)(context->bit_len >> (i * 8));
    sha256_transform(context, context->data);

    for (int i = 0; i < 8; ++i) {
        digest[i * 4] = (uint8_t)(context->state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(context->state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(context->state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)context->state[i];
    }
}

static void sha256(const char *text, uint8_t digest[32]) {
    Sha256Context context;
    sha256_init(&context);
    sha256_update(&context, (const uint8_t *)text, strlen(text));
    sha256_final(&context, digest);
}

static int sha256_self_test(void) {
    static const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    uint8_t actual[32];
    sha256("abc", actual);
    return memcmp(actual, expected, sizeof(expected)) == 0;
}

static char *trim(char *text) {
    char *end;
    while (isspace((unsigned char)*text)) ++text;
    if (*text == '\0') return text;
    end = text + strlen(text) - 1;
    while (end > text && isspace((unsigned char)*end)) --end;
    end[1] = '\0';
    return text;
}

static int hex_value(char character) {
    if (character >= '0' && character <= '9') return character - '0';
    character = (char)tolower((unsigned char)character);
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    return -1;
}

static int load_hash(const char *path, uint8_t target[32]) {
    FILE *file = fopen(path, "r");
    char line[MAX_LINE];
    if (!file) return 0;

    while (fgets(line, sizeof(line), file)) {
        char *value = trim(line);
        if (*value == '\0') continue;
        if (strlen(value) != 64) {
            fclose(file);
            return 0;
        }
        for (int i = 0; i < 32; ++i) {
            int high = hex_value(value[i * 2]);
            int low = hex_value(value[i * 2 + 1]);
            if (high < 0 || low < 0) {
                fclose(file);
                return 0;
            }
            target[i] = (uint8_t)((high << 4) | low);
        }
        fclose(file);
        return 1;
    }
    fclose(file);
    return 0;
}

static int parse_positive_int(const char *text, int *result) {
    char *end;
    long value = strtol(text, &end, 10);
    if (*text == '\0' || *end != '\0' || value < 1 || value > 7) return 0;
    *result = (int)value;
    return 1;
}

static int parse_rule(char *line, Rule *rule) {
    char *value = trim(line);
    char *argument;
    memset(rule, 0, sizeof(*rule));
    if (*value == '\0' || *value == '#') return 0;

    if (strcmp(value, "base") == 0) rule->type = RULE_BASE;
    else if (strcmp(value, "lower_suffix") == 0) rule->type = RULE_LOWER_SUFFIX;
    else if (strcmp(value, "upper_suffix") == 0) rule->type = RULE_UPPER_SUFFIX;
    else if (strcmp(value, "capitalize_suffix") == 0) rule->type = RULE_CAPITALIZE_SUFFIX;
    else if (strcmp(value, "leet_suffix") == 0) rule->type = RULE_LEET_SUFFIX;
    else if (strcmp(value, "reverse_suffix") == 0) rule->type = RULE_REVERSE_SUFFIX;
    else if (strncmp(value, "append_digits=", 14) == 0) {
        rule->type = RULE_APPEND_DIGITS;
        if (!parse_positive_int(value + 14, &rule->first)) return -1;
    } else if (strncmp(value, "leet_append_digits=", 19) == 0) {
        rule->type = RULE_LEET_APPEND_DIGITS;
        if (!parse_positive_int(value + 19, &rule->first)) return -1;
    } else if (strncmp(value, "capitalize_append_digits=", 25) == 0) {
        rule->type = RULE_CAPITALIZE_APPEND_DIGITS;
        if (!parse_positive_int(value + 25, &rule->first)) return -1;
    } else if (strncmp(value, "append_years=", 13) == 0) {
        rule->type = RULE_APPEND_YEARS;
        argument = value + 13;
        if (sscanf(argument, "%d-%d", &rule->first, &rule->last) != 2 ||
            rule->first < 0 || rule->last < rule->first ||
            rule->last - rule->first > 500) return -1;
    } else if (strncmp(value, "append_symbols=", 15) == 0) {
        rule->type = RULE_APPEND_SYMBOLS;
        argument = value + 15;
        if (*argument == '\0' || strlen(argument) >= sizeof(rule->text)) return -1;
        strcpy(rule->text, argument);
    } else {
        return -1;
    }
    return 1;
}

static int load_rules(const char *path, Rule rules[MAX_RULES], size_t *count) {
    FILE *file = fopen(path, "r");
    char line[MAX_LINE];
    int line_number = 0;
    *count = 0;
    if (!file) return 0;

    while (fgets(line, sizeof(line), file)) {
        Rule rule;
        int parsed;
        ++line_number;
        parsed = parse_rule(line, &rule);
        if (parsed < 0) {
            fprintf(stderr, "Regra invalida na linha %d: %s", line_number, line);
            fclose(file);
            return 0;
        }
        if (parsed == 0) continue;
        if (*count >= MAX_RULES) {
            fprintf(stderr, "O arquivo excede o limite de %d regras.\n", MAX_RULES);
            fclose(file);
            return 0;
        }
        rules[(*count)++] = rule;
    }
    fclose(file);
    return *count > 0;
}

static int make_prefixed(const char *word, const char *prefix, char output[MAX_CANDIDATE]) {
    size_t prefix_len = strlen(prefix);
    size_t word_len = strlen(word);
    int already_prefixed = word_len >= prefix_len && strncmp(word, prefix, prefix_len) == 0;
    size_t needed = word_len + (already_prefixed ? 0 : prefix_len) + 1;
    if (needed > MAX_CANDIDATE) return 0;
    output[0] = '\0';
    if (!already_prefixed) strcat(output, prefix);
    strcat(output, word);
    return 1;
}

static void lower_suffix(char *candidate, size_t prefix_len) {
    for (size_t i = prefix_len; candidate[i]; ++i)
        candidate[i] = (char)tolower((unsigned char)candidate[i]);
}

static void upper_suffix(char *candidate, size_t prefix_len) {
    for (size_t i = prefix_len; candidate[i]; ++i)
        candidate[i] = (char)toupper((unsigned char)candidate[i]);
}

static void capitalize_suffix(char *candidate, size_t prefix_len) {
    lower_suffix(candidate, prefix_len);
    if (candidate[prefix_len])
        candidate[prefix_len] = (char)toupper((unsigned char)candidate[prefix_len]);
}

static void leet_suffix(char *candidate, size_t prefix_len) {
    for (size_t i = prefix_len; candidate[i]; ++i) {
        switch ((char)tolower((unsigned char)candidate[i])) {
            case 'a': candidate[i] = '4'; break;
            case 'e': candidate[i] = '3'; break;
            case 'i': candidate[i] = '1'; break;
            case 'o': candidate[i] = '0'; break;
            case 's': candidate[i] = '5'; break;
            case 't': candidate[i] = '7'; break;
            default: break;
        }
    }
}

static void reverse_suffix(char *candidate, size_t prefix_len) {
    size_t end = strlen(candidate);
    if (end <= prefix_len) return;
    --end;
    while (prefix_len < end) {
        char temporary = candidate[prefix_len];
        candidate[prefix_len++] = candidate[end];
        candidate[end--] = temporary;
    }
}

static int try_candidate(SearchContext *search, const char *candidate) {
    uint8_t digest[32];
    if (search->found) return 1;
    sha256(candidate, digest);
    ++search->attempts;
    if (memcmp(digest, search->target, sizeof(digest)) == 0) {
        search->found = 1;
        snprintf(search->password, sizeof(search->password), "%s", candidate);
        return 1;
    }
    return 0;
}

static int append_and_try(SearchContext *search, const char *base, const char *suffix) {
    char candidate[MAX_CANDIDATE];
    int written = snprintf(candidate, sizeof(candidate), "%s%s", base, suffix);
    if (written < 0 || (size_t)written >= sizeof(candidate)) return 0;
    return try_candidate(search, candidate);
}

static int try_number_range(SearchContext *search, const char *base, int digits) {
    int limit = 1;
    char suffix[16];
    for (int i = 0; i < digits; ++i) limit *= 10;
    for (int value = 0; value < limit; ++value) {
        snprintf(suffix, sizeof(suffix), "%0*d", digits, value);
        if (append_and_try(search, base, suffix)) return 1;
    }
    return 0;
}

static int apply_rule(SearchContext *search, const Rule *rule,
                      const char *canonical, size_t prefix_len) {
    char transformed[MAX_CANDIDATE];
    snprintf(transformed, sizeof(transformed), "%s", canonical);

    switch (rule->type) {
        case RULE_BASE:
            return try_candidate(search, transformed);
        case RULE_LOWER_SUFFIX:
            lower_suffix(transformed, prefix_len);
            return try_candidate(search, transformed);
        case RULE_UPPER_SUFFIX:
            upper_suffix(transformed, prefix_len);
            return try_candidate(search, transformed);
        case RULE_CAPITALIZE_SUFFIX:
            capitalize_suffix(transformed, prefix_len);
            return try_candidate(search, transformed);
        case RULE_LEET_SUFFIX:
            leet_suffix(transformed, prefix_len);
            return try_candidate(search, transformed);
        case RULE_REVERSE_SUFFIX:
            reverse_suffix(transformed, prefix_len);
            return try_candidate(search, transformed);
        case RULE_APPEND_DIGITS:
            return try_number_range(search, transformed, rule->first);
        case RULE_LEET_APPEND_DIGITS:
            leet_suffix(transformed, prefix_len);
            return try_number_range(search, transformed, rule->first);
        case RULE_CAPITALIZE_APPEND_DIGITS:
            capitalize_suffix(transformed, prefix_len);
            return try_number_range(search, transformed, rule->first);
        case RULE_APPEND_YEARS: {
            char suffix[16];
            for (int year = rule->first; year <= rule->last; ++year) {
                snprintf(suffix, sizeof(suffix), "%d", year);
                if (append_and_try(search, transformed, suffix)) return 1;
            }
            return 0;
        }
        case RULE_APPEND_SYMBOLS:
            for (size_t i = 0; rule->text[i]; ++i) {
                char suffix[2] = {rule->text[i], '\0'};
                if (append_and_try(search, transformed, suffix)) return 1;
            }
            return 0;
    }
    return 0;
}

static double elapsed_seconds(struct timespec start, struct timespec end) {
    return (double)(end.tv_sec - start.tv_sec) +
           (double)(end.tv_nsec - start.tv_nsec) / 1000000000.0;
}

int main(int argc, char **argv) {
    const char *prefix;
    FILE *wordlist;
    Rule rules[MAX_RULES];
    size_t rule_count;
    SearchContext search = {0};
    char line[MAX_LINE];
    uint64_t words = 0;
    struct timespec started_at, ended_at;

    if (argc < 4 || argc > 5) {
        fprintf(stderr, "Uso: %s HASH_FILE WORDLIST RULES [PREFIXO]\n", argv[0]);
        return 2;
    }
    if (!sha256_self_test()) {
        fprintf(stderr, "Erro: a autoverificacao do SHA-256 falhou.\n");
        return 2;
    }
    prefix = argc == 5 ? argv[4] : "pe";
    if (*prefix == '\0' || strlen(prefix) >= MAX_CANDIDATE) {
        fprintf(stderr, "Erro: prefixo invalido.\n");
        return 2;
    }
    if (!load_hash(argv[1], search.target)) {
        fprintf(stderr, "Erro: hash SHA-256 hexadecimal invalido em '%s'.\n", argv[1]);
        return 2;
    }
    if (!load_rules(argv[3], rules, &rule_count)) {
        fprintf(stderr, "Erro: nao foi possivel carregar regras validas de '%s'.\n", argv[3]);
        return 2;
    }
    wordlist = fopen(argv[2], "r");
    if (!wordlist) {
        fprintf(stderr, "Erro: nao foi possivel abrir o dicionario '%s'.\n", argv[2]);
        return 2;
    }

    timespec_get(&started_at, TIME_UTC);
    while (!search.found && fgets(line, sizeof(line), wordlist)) {
        char canonical[MAX_CANDIDATE];
        char *word = trim(line);
        if (*word == '\0' || *word == '#') continue;
        if (!make_prefixed(word, prefix, canonical)) {
            fprintf(stderr, "Aviso: palavra longa demais, ignorada.\n");
            continue;
        }
        ++words;
        for (size_t i = 0; i < rule_count && !search.found; ++i)
            apply_rule(&search, &rules[i], canonical, strlen(prefix));
    }
    fclose(wordlist);
    timespec_get(&ended_at, TIME_UTC);

    double elapsed = elapsed_seconds(started_at, ended_at);
    double rate = elapsed > 0.0 ? (double)search.attempts / elapsed : 0.0;
    printf("Status: %s\n", search.found ? "Cracked" : "Exhausted");
    if (search.found) printf("Senha: %s\n", search.password);
    printf("Palavras do dicionario: %llu\n", (unsigned long long)words);
    printf("Regras carregadas: %llu\n", (unsigned long long)rule_count);
    printf("Tentativas: %llu\n", (unsigned long long)search.attempts);
    printf("Tempo: %.6f s\n", elapsed);
    printf("Velocidade: %.0f tentativas/s\n", rate);
    return search.found ? 0 : 1;
}
