#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable : 4996)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <time.h>

#include <openssl/applink.c>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/objects.h>

#pragma comment(lib, "crypt32")
#pragma comment(lib, "ws2_32.lib")

//f1
int hexDecimal(char hex) {
    if (hex >= '0' && hex <= '9') {
        return hex - '0';
    }
    else if (hex >= 'a' && hex <= 'f') {
        return hex - 'a' + 10;
    }
    return -1;
}

unsigned char* hexBin(const char* hex_string, int* len) {
    int hex_len = strlen(hex_string);
    if (hex_len % 2 != 0) {
        printf("Length must be even.\n");
        return NULL;
    }

    *len = hex_len / 2;
    unsigned char* binData = (unsigned char*)malloc(*len);

    for (int i = 0; i < *len; ++i) {
        int firstHalf = hexDecimal(hex_string[i * 2]);
        int secondHalf = hexDecimal(hex_string[i * 2 + 1]);
        if (firstHalf == -1 || secondHalf == -1) {
            printf("There's a non hex character somewhere.\n");
            free(binData);
            return NULL;
        }
        binData[i] = ((firstHalf << 4) ^ secondHalf);
    }

    return binData;
}

char binary_to_hex(unsigned char bin) {
    if (bin >= 0 && bin <= 9) {
        return '0' + bin;
    }
    else if (bin >= 10 && bin <= 15) {
        return 'a' + (bin - 10);
    }
    return -1;
}

char* binHex(const unsigned char* bin_data, int len) {
    char* hex_string = (char*)malloc(len * 2 + 1);
    if (hex_string == NULL) {
        printf("Memory allocation failed.\n");
        return NULL;
    }

    for (int i = 0; i < len; ++i) {
        hex_string[i * 2] = binary_to_hex(bin_data[i] >> 4); // first 4 bits
        hex_string[i * 2 + 1] = binary_to_hex(bin_data[i] & 0x0F); // last 4
    }
    hex_string[len * 2] = '\0';

    return hex_string;
}

void f1() {
    //f1
    const char* hex_string = "abcd1234ffde8764";
    
    //hex to bin
    int bin_len;
    unsigned char* binary_data = hexBin(hex_string, &bin_len);

    printf("Binary data: ");
    for (int i = 0; i < bin_len; i++) {
        printf("%.02x", binary_data[i]);
    }
    printf("\n");

    //bin to hex
    char* hex_result = binHex(binary_data, bin_len);

    printf("Hex string: %s\n", hex_result);

    free(binary_data);
    free(hex_result);

}

//f2
typedef struct Embeded_Key {
    ASN1_INTEGER* numar_1;
    ASN1_INTEGER* numar_2;
    ASN1_INTEGER* numar_3;
    ASN1_INTEGER* numar_4;
    ASN1_INTEGER* numar_5;
} Embeded_Key;

typedef struct Master_Key {
    ASN1_PRINTABLESTRING* CommonName;
    ASN1_PRINTABLESTRING* Subject;
    ASN1_INTEGER* Key_ID;
    Embeded_Key* Key;
} Master_Key;

ASN1_SEQUENCE(Embeded_Key) = {
    ASN1_SIMPLE(Embeded_Key, numar_1, ASN1_INTEGER),
    ASN1_SIMPLE(Embeded_Key, numar_2, ASN1_INTEGER),
    ASN1_SIMPLE(Embeded_Key, numar_3, ASN1_INTEGER),
    ASN1_SIMPLE(Embeded_Key, numar_4, ASN1_INTEGER),
    ASN1_SIMPLE(Embeded_Key, numar_5, ASN1_INTEGER)
} ASN1_SEQUENCE_END(Embeded_Key)

DECLARE_ASN1_FUNCTIONS(Embeded_Key);
IMPLEMENT_ASN1_FUNCTIONS(Embeded_Key);

ASN1_SEQUENCE(Master_Key) = {
    ASN1_SIMPLE(Master_Key, CommonName, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(Master_Key, Subject, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(Master_Key, Key_ID, ASN1_INTEGER),
    ASN1_EMBED(Master_Key, Key, Embeded_Key)
} ASN1_SEQUENCE_END(Master_Key)

DECLARE_ASN1_FUNCTIONS(Master_Key);
IMPLEMENT_ASN1_FUNCTIONS(Master_Key);

//https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
int modInverse(long int A, long int M)
{
    for (int X = 1; X < M; X++)
        if (((A % M) * (X % M)) % M == 1)
            return X;
    return -1;
}

BIGNUM* generate_prime(int min_bits, int max_bits) {
    BIGNUM* prime = BN_new();

    int rc = BN_generate_prime_ex(prime, max_bits, 0, NULL, NULL, NULL);

    while (BN_num_bits(prime) < min_bits) {
        BN_free(prime);
        prime = BN_new();
        rc = BN_generate_prime_ex(prime, max_bits, 0, NULL, NULL, NULL);

    }

    return prime;
}

void f2() {
    //f2
    auto cheie_master = Master_Key_new();
    const char* nume = "Mihai";
    const char* subiect = "cripto";
    int key_id = 1;

    ASN1_STRING_set(cheie_master->CommonName, nume, strlen(nume));
    ASN1_STRING_set(cheie_master->Subject, subiect, strlen(subiect));
    ASN1_INTEGER_set(cheie_master->Key_ID, key_id);

    srand(time(NULL));
    auto cheie_embeded = Embeded_Key_new();

    BIGNUM* nr1 = generate_prime(20, 31);
    BIGNUM* nr2 = generate_prime(20, 31);

    long int nr1_int = atoi(BN_bn2dec(nr1));
    long int nr2_int = atoi(BN_bn2dec(nr2));
    printf("Nr1: %d Nr2: %d\n", nr1_int, nr2_int);

    long int nr3;
    long long int nr5, nr4;
    nr3 = (rand() % nr1_int) * 2 + 1;
    nr4 = modInverse(nr3, (nr1_int - 1) * (nr2_int - 1));
    nr5 = nr1_int * nr2_int;
    printf("Nr3: %d Nr4: %d Nr5: %d\n", nr3, nr4 ,nr5);

    ASN1_INTEGER_set(cheie_embeded->numar_1, nr1_int);
    ASN1_INTEGER_set(cheie_embeded->numar_2, nr2_int);
    ASN1_INTEGER_set(cheie_embeded->numar_3, nr3);
    ASN1_INTEGER_set(cheie_embeded->numar_4, nr4);
    ASN1_INTEGER_set(cheie_embeded->numar_5, nr5);
    //de obicei crapa pentru ca se depaseste dimensiunea int-ului

    Embeded_Key_free(cheie_embeded);
    Master_Key_free(cheie_master);
}

//f3

int f3(int argc, char **argv) {
    printf("Enc:%s In:%s Key:%s Out:%s da:%s IV:%s\n", argv[1], argv[2], argv[3], argv[4], argv[5], argv[6]);

    FILE* f = fopen(argv[3], "rb");
    if (!f) {
        printf("Nu s-a putut deschide fisierul %s\n", argv[3]);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    int keyLen = ftell(f);
    printf("key length %d\n", keyLen);

    if (!(keyLen == 32 || keyLen == 16 || keyLen == 24)) {
        printf("Lungime invalida de cheie");
        return -1;
    }
    rewind(f);
    unsigned char* key = (unsigned char*)malloc(keyLen);
    fread(key, 1, keyLen, f);
    fclose(f);

    f = fopen(argv[2], "rb");
    if (!f) {
        printf("Nu s-a putut deschide fisierul %s\n", argv[2]);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    int fileSize = ftell(f);
    rewind(f);

    //plain text
    unsigned char* pt = (unsigned char*)malloc(fileSize);
    if (!pt) {
        printf("Eroare la alocarea memoriei pentru citirea fisierului\n");
        fclose(f);
        return 1;
    }

    fread(pt, 1, fileSize, f);
    fclose(f);

    unsigned char* iv = (unsigned char*)_strdup(argv[6]);

    printf("IV-ul\n");
    printf("%s\n", iv);
    //printf("Cheia:\n");
    //printf("%s\n", key);

    AES_KEY aesKey;
    AES_set_encrypt_key(key, keyLen * 8, &aesKey);
    unsigned char *keyStr = new unsigned char[16];
    unsigned char* out = new unsigned char[fileSize];//unde pun datele criptate
    int i;
    for (i = 0; i < fileSize / 16; i++)//pt nr de blocuri criptam iv-ul
    {
        AES_encrypt(iv, keyStr, &aesKey);//generarea cheilor de runda
        //operatia de xor
        //keystr
        if (keyStr[15] + 5 > 0xFF) {
            int index = 14;

            while (index >= 0 && keyStr[index] + 1 > 0xFF) {
                index--; // Trecem la octetul anterior
            }

            if (index >= 0) {
                keyStr[index]++;
            }
        }
        else {
            keyStr[15] += 5;
        }
        for (int j = 0; j < 16; j++)
        {
            out[i * 16 + j] = keyStr[j] ^ pt[i * 16 + j];
        }
        memcpy(iv, out + i * 16, 16);// ct1 devine noul iv pentru urmatoarea iteratie
    }
    AES_encrypt(iv, keyStr, &aesKey);//generarea cheilor de runda
    //operatia de xor
    if (keyStr[15] + 5 > 0xFF) {
        int index = 14;

        while (index >= 0 && keyStr[index] + 1 > 0xFF) {
            index--; // Trecem la octetul anterior
        }

        if (index >= 0) {
            keyStr[index]++;
        }
    }
    else {
        keyStr[15] += 5;
    }
    for (int j = 0; j < fileSize % 16; j++)
    {
        out[i * 16 + j] = keyStr[j] ^ pt[i * 16 + j];
    }
    printf("Rezultat AES_old:\n");
    unsigned char* output = new unsigned char[fileSize + 1];
    for (int j = 0; j < fileSize; j++)
    {
        printf("%.02x", out[j]);
        output[j] = out[j];
    }

    output[fileSize + 1] = '\0';

    f = fopen(argv[4], "wb");
    fprintf(f, (const char*)output);
}

//f4
typedef struct Packet {
    ASN1_OCTET_STRING* EncMessage;
    ASN1_UTCTIME* TimeStamp;
    ASN1_PRINTABLESTRING* AuthData;
    ASN1_OCTET_STRING* Tag;
    ASN1_OCTET_STRING* Algorithm;
} Packet;

ASN1_SEQUENCE(Packet) = {
    ASN1_SIMPLE(Packet, EncMessage, ASN1_OCTET_STRING),
    ASN1_SIMPLE(Packet, TimeStamp, ASN1_UTCTIME),
    ASN1_SIMPLE(Packet, AuthData, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(Packet, Tag, ASN1_OCTET_STRING),
    ASN1_SIMPLE(Packet, Algorithm, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(Packet)

DECLARE_ASN1_FUNCTIONS(Packet);
IMPLEMENT_ASN1_FUNCTIONS(Packet);

void encodeBase64(const unsigned char* input, int inputLen, char* output) {
    const char* base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

}

void encryptMessage(unsigned char* message, int messageLen, unsigned char* key, unsigned char* iv,
    unsigned char* encryptedMessage, unsigned char* tag, char* algorithm) {

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertextLen;

    if (strcmp(algorithm, "AES-256-GCM") == 0) {
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
        EVP_EncryptUpdate(ctx, encryptedMessage, &len, message, messageLen);
        EVP_EncryptFinal_ex(ctx, encryptedMessage + len, &ciphertextLen);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    }
    else if (strcmp(algorithm, "ChaCha20_Poly1305") == 0) {
        EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
        EVP_EncryptUpdate(ctx, encryptedMessage, &len, message, messageLen);
        EVP_EncryptFinal_ex(ctx, encryptedMessage + len, &ciphertextLen);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag);
    }

    EVP_CIPHER_CTX_free(ctx);
}

void sendPacket(Packet* packet, char* recipient) {
    printf("Sending packet to %s:\n", recipient);
    printf("Encrypted Message: ");
    for (int i = 0; i < packet->EncMessage->length; i++) {
        printf("%02x", packet->EncMessage->data[i]);
    }
    printf("\n");
    printf("Timestamp: %s\n", packet->TimeStamp->data);
    printf("Auth Data: %s\n", packet->AuthData->data);
    printf("Tag: ");
    for (int i = 0; i < packet->Tag->length; i++) {
        printf("%02x", packet->Tag->data[i]);
    }
    printf("\n");
    printf("Algorithm: %s\n", packet->Algorithm->data);
}

int f4(int argc, char** argv)
{
    Packet* packet = Packet_new();
    packet->EncMessage = ASN1_OCTET_STRING_new();
    packet->TimeStamp = ASN1_UTCTIME_new();
    packet->AuthData = ASN1_PRINTABLESTRING_new();
    packet->Tag = ASN1_OCTET_STRING_new();
    packet->Algorithm = ASN1_OCTET_STRING_new();

    return 0;
}

//f5
unsigned char generate_byte_state(unsigned char seed) {
    return (seed * 5 + 1) % 256;
}

unsigned char shift_right(unsigned char byte, int shift_amount) {
    return byte >> shift_amount;
}


unsigned char shift_left(unsigned char byte, int shift_amount) {
    return byte << shift_amount;
}


unsigned char xor_operation(unsigned char byte1, unsigned char byte2) {
    return byte1 ^ byte2;
}

unsigned char confusion_operation(unsigned char byte) {
    return ((byte & 0x0F) << 6) | ((byte & 0xF0) >> 2);
}

unsigned char diffusion_operation(unsigned char byte) {
    return (byte << 1) | (byte >> 7);
}

void generate_keystream(unsigned char seed, int stream_length) {
    unsigned char byte_state = seed;

    for (int i = 0; i < stream_length; i++) {
        byte_state = generate_byte_state(byte_state);

        byte_state = shift_right(byte_state, 2);

        byte_state = shift_left(byte_state, 3);

        byte_state = xor_operation(byte_state, 0xFF);
        byte_state = confusion_operation(byte_state);
        byte_state = diffusion_operation(byte_state);

        printf("%02X ", byte_state);
    }
    printf("\n");
}

int f5(int argc, char** argv)
{
    unsigned char seed = 0x61;
    int stream_length = 15;

    printf("Keystream generat:\n");
    generate_keystream(seed, stream_length);

    return 0;
}


int main(int argc, char** argv) {
    int status = 0;
    //f1();
    //f2();
    //status = f3(argc, argv);
    status = f4(argc, argv);
    //status = f5(argc, argv);



    return status;
}
