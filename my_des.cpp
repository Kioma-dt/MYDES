#include <iostream>
#include <bitset>
#include <stdint.h>
#include <ctime>

using u8  = uint8_t;
using u32 = uint32_t;
using u64 = uint64_t;

template <std::size_t N>
class BitSet {
    std::bitset<N> _bits;

public:
    BitSet()
        : _bits()
    {}

    BitSet(u64 bits)
        : _bits(bits)
    {}

    bool operator[](size_t n){
        return _bits[N - n];
    }

    u64 GetNumDec(){
        return _bits.to_ullong();
    }

    std::string GetNumBin(){
        return _bits.to_string();
    }

    template<std::size_t count>
    BitSet<count> GetSubBitSet(size_t from, size_t to){
        u64 sub_bit_set = 0;
        for (int i = from; i <= to; i++){
            sub_bit_set <<= 1;
            sub_bit_set |= (*this)[i];
        }
        return BitSet<count>(sub_bit_set);
    }
};

template<std::size_t N>
bool GetBit(std::bitset<N> bits, size_t n){
    return bits[N - n];
}

template<std::size_t N, std::size_t count>
    std::bitset<count> GetSubBitSet(std::bitset<N> bits, size_t from, size_t to){
        u64 sub_bit_set = 0;
        for (int i = from; i <= to; i++){
            sub_bit_set <<= 1;
            sub_bit_set |= GetBit<N>(bits, i);
        }
        return std::bitset<count>(sub_bit_set);
    }

static const u8 KeyRolling[16] = {
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
};

static const u8 PC2[48] = {
        14,17,11,24,1,5,
        3,28,15,6,21,10,
        23,19,12,4,26,8,
        16,7,27,20,13,2,
        41,52,31,37,47,55,
        30,40,51,45,33,48,
        44,49,39,56,34,53,
        46,42,50,36,29,32
};

static const u8 E[48] = {
            32,1,2,3,4,5,
            4,5,6,7,8,9,
            8,9,10,11,12,13,
            12,13,14,15,16,17,
            16,17,18,19,20,21,
            20,21,22,23,24,25,
            24,25,26,27,28,29,
            28,29,30,31,32,1
};

static const u8 P[32] = {
        16,7,20,21,29,12,28,17,
        1,15,23,26,5,18,31,10,
        2,8,24,14,32,27,3,9,
        19,13,30,6,22,11,4,25    
};

static const u32 SP1[64] = {
    0x01010400,0x00000000,0x00010000,0x01010404,0x01010004,0x00010404,0x00000004,0x00010000,
    0x00000400,0x01010404,0x01010400,0x00000400,0x01000404,0x01010004,0x01000000,0x00000004,
    0x00000404,0x01000400,0x01000400,0x00010400,0x00010400,0x01010000,0x01010000,0x01000404,
    0x00010004,0x01000004,0x01000004,0x00010004,0x00000000,0x00000404,0x00010404,0x01000000,
    0x00010000,0x01010400,0x00000004,0x01010004,0x01010404,0x01000000,0x01000000,0x00000400,
    0x01010000,0x00010000,0x00010400,0x01000004,0x00000400,0x00000004,0x01000404,0x00010404,
    0x01010400,0x01010000,0x01000004,0x00000404,0x01010004,0x00010400,0x00000404,0x01010404,
    0x00010404,0x00000000,0x00010004,0x01000404,0x00000000,0x01000400,0x01000400,0x00010004
};

static const u32 SP2[64] = {
    0x80108020,0x80008000,0x00008000,0x00108020,0x00100000,0x00000020,0x80100020,0x80008020,
    0x80000020,0x80108020,0x80108000,0x80000000,0x80008000,0x00100000,0x00000020,0x80100020,
    0x00108000,0x00100020,0x80008020,0x00000000,0x80000000,0x00008000,0x00108020,0x80100000,
    0x00100020,0x80000020,0x00000000,0x00108000,0x00008020,0x80108000,0x80100000,0x00008020,
    0x00000000,0x00108020,0x80100020,0x00100000,0x80008020,0x80100000,0x80108000,0x00008000,
    0x80100000,0x80008000,0x00000020,0x80108020,0x00108020,0x00000020,0x00008000,0x80000000,
    0x00008020,0x80108000,0x00100000,0x00008020,0x80108000,0x00000000,0x80000020,0x00100020,
    0x80000000,0x80100020,0x00108000,0x80000020,0x00100020,0x80008020,0x80100000,0x00108000
};

static const u32 SP3[64] = {
    0x00000208,0x08020200,0x00000000,0x08020008,0x08000200,0x00000000,0x00020208,0x08000200,
    0x00020008,0x08000008,0x08000008,0x00020000,0x08020208,0x00020008,0x08020000,0x00000208,
    0x08000000,0x00000008,0x08020200,0x00000200,0x00020200,0x08020000,0x08020008,0x00020208,
    0x08000208,0x00020200,0x00020000,0x08000208,0x00000008,0x08020208,0x00000200,0x08000000,
    0x08020200,0x08000000,0x00020008,0x00000208,0x00000200,0x00020008,0x08000200,0x00000000,
    0x08020008,0x00000200,0x08020208,0x08000200,0x00000000,0x08020200,0x00020208,0x08020008,
    0x08000008,0x00020000,0x08000208,0x00020208,0x00020000,0x08000208,0x00000008,0x08020000,
    0x00020200,0x08020208,0x08020000,0x08000008,0x00000208,0x00020200,0x08000000,0x00000008
};

static const u32 SP4[64] = {
    0x00802001,0x00002081,0x00002081,0x00000080,0x00802080,0x00800081,0x00800001,0x00002001,
    0x00000000,0x00802000,0x00802000,0x00802081,0x00000081,0x00800001,0x00000080,0x00800080,
    0x00000081,0x00800080,0x00800080,0x00000081,0x00800001,0x00002000,0x00002001,0x00800001,
    0x00802001,0x00000080,0x00002080,0x00800000,0x00002001,0x00000000,0x00802000,0x00002080,
    0x00800000,0x00802001,0x00002081,0x00800000,0x00802081,0x00000080,0x00000080,0x00802081,
    0x00000000,0x00002081,0x00800080,0x00000081,0x00802000,0x00800080,0x00002080,0x00802000,
    0x00002080,0x00800001,0x00800001,0x00002000,0x00000081,0x00802080,0x00802080,0x00000081,
    0x00800001,0x00002001,0x00002001,0x00000000,0x00802081,0x00002080,0x00000000,0x00802081
};

static const u32 SP5[64] = {
    0x00000100,0x02080100,0x02080000,0x42000100,0x00080000,0x00000100,0x40000000,0x02080000,
    0x40080100,0x00080000,0x02000100,0x40080100,0x42000100,0x42080000,0x00080100,0x40000000,
    0x02000000,0x40080000,0x40080000,0x00000000,0x40000100,0x42080100,0x42080100,0x40000100,
    0x42080000,0x02000000,0x00000000,0x42000100,0x02080100,0x02000000,0x42000000,0x00080100,
    0x40000000,0x02080000,0x00000100,0x02000000,0x02000100,0x40000000,0x42000100,0x02080100,
    0x40080100,0x00000100,0x42080000,0x02000100,0x00080000,0x42000000,0x02000000,0x42080100,
    0x42000000,0x00080000,0x40080000,0x42000000,0x00080100,0x40080100,0x02080100,0x00000000,
    0x42080100,0x00080100,0x00000000,0x42080000,0x40000100,0x02080100,0x40080000,0x00000100
};

static const u32 SP6[64] = {
    0x20000010,0x20400000,0x00004000,0x20404010,0x20400000,0x00000010,0x20404010,0x00400000,
    0x20004000,0x00404010,0x00400000,0x20000010,0x00404000,0x20004000,0x20000000,0x00004010,
    0x00000000,0x00400000,0x20004010,0x00004000,0x00400010,0x20004010,0x00000010,0x20000000,
    0x00004010,0x20404000,0x00404010,0x00000010,0x20404000,0x20000010,0x20004000,0x00404000,
    0x20400010,0x00004000,0x00400000,0x20400010,0x20000000,0x00404010,0x00004010,0x20004000,
    0x00404000,0x20000000,0x20404000,0x00404000,0x20004010,0x20404010,0x20400000,0x00000000,
    0x00004000,0x00400010,0x20000010,0x00004010,0x00400010,0x20404000,0x00000000,0x20400000,
    0x20404010,0x20004010,0x00404010,0x20000010,0x00000010,0x20400000,0x20404000,0x00400010
};

static const u32 SP7[64] = {
    0x00200000,0x04200002,0x04000802,0x00000000,0x00000800,0x04000802,0x00200802,0x04200800,
    0x04200802,0x00200000,0x00000000,0x04000002,0x00200002,0x04000000,0x04200000,0x00000802,
    0x04000800,0x00200802,0x00200002,0x04000800,0x04000002,0x04200000,0x04200800,0x00200002,
    0x04200002,0x00000800,0x00000802,0x04200802,0x00200800,0x00000002,0x00000002,0x00200800,
    0x04000000,0x00200800,0x04200802,0x04000002,0x00200000,0x04000800,0x00000800,0x04200002,
    0x00200802,0x04200800,0x04000002,0x04200000,0x00000002,0x00000802,0x04200000,0x00000000,
    0x04200800,0x00000002,0x00000802,0x00200002,0x00200002,0x04000000,0x04000802,0x00000800,
    0x00000000,0x00200802,0x04200002,0x00000002,0x04000800,0x04200802,0x00200800,0x04000000
};

static const u32 SP8[64] = {
    0x10001040,0x00001000,0x00040000,0x10041040,0x10000000,0x10001040,0x00000040,0x10000000,
    0x00040040,0x10040000,0x10041040,0x00041000,0x10001000,0x00000040,0x00001000,0x10040040,
    0x00041040,0x10041000,0x10041000,0x00001040,0x10040000,0x00040040,0x00000040,0x10001000,
    0x00000000,0x00041040,0x10040040,0x00040000,0x10001040,0x00000000,0x00041000,0x10001040,
    0x00041000,0x10040040,0x10001000,0x00000040,0x00001040,0x10041040,0x00040000,0x10000040,
    0x10040040,0x10000000,0x00001000,0x10041000,0x00000040,0x00001040,0x10000040,0x00041000,
    0x10041040,0x00040040,0x10000000,0x00001000,0x10040000,0x10001040,0x00041040,0x00040000,
    0x00001040,0x10040000,0x10041000,0x10000040,0x10000040,0x00000000,0x00000000,0x10041040
};

std::bitset<56> RolKey(std::bitset<56> key, int round)
{
    u8 shift = KeyRolling[round];
    std::bitset<28> mask = 0x0fffffff;

    std::bitset<28> first_half = GetSubBitSet<56, 28>(key, 1, 28);
    std::bitset<28> second_half = GetSubBitSet<56, 28>(key, 29, 56);

    std::bitset<56> rol_key = (((first_half << shift | first_half >> (28 - shift)) & mask).to_ullong() << 28 |
                ((second_half << shift | second_half >> (28 - shift)) & mask).to_ullong());

    return rol_key;
}

std::bitset<48> ApplyPC2(std::bitset<56> key){

    std::bitset<48> sub_key(0);
    for (int i = 1; i <= 48; i++){
        u8 bit_number = PC2[i - 1];
        sub_key[48 - i] = GetBit<56>(key, bit_number);
    }

    return std::bitset<48>(sub_key);
}

std::bitset<48>* CooKeys(std::bitset<56> des_key){
    std::bitset<48> *cookeys = new std::bitset<48>[16];
    for (int i = 0; i < 16; i++){
        des_key = RolKey(des_key, i);
        cookeys[i] = ApplyPC2(des_key);
    }

    return cookeys;
}

std::bitset<64> DesFunc(std::bitset<64> plain_text, std::bitset<48>* cookeys){
    std::bitset<32> left = std::bitset<32>((plain_text.to_ullong() >> 32) & 0xFFFFFFFF);
    std::bitset<32> right = std::bitset<32>(plain_text.to_ullong() & 0xFFFFFFFF);

    for (int i = 0; i < 16; i++){
        // E - table
        std::bitset<48> b_e = 0;
        for (int j = 1; j <= 48; j++){
            u8 bit_number = E[j - 1];
            b_e[48 - j] = GetBit<32>(right, bit_number);
        }

        // XOR KEY
        std::bitset<48> b_k = b_e ^ cookeys[i];

        // S - table
        std::bitset<32> b_s = 0;
        for (int s = 0; s < 8; s++){
            std::bitset<6> b = GetSubBitSet<48, 6>(b_k, s * 6 + 1, (s + 1) * 6);

            u8 row = (GetBit<6>(b,1) << 1) | 
                    (GetBit<6>(b,6));
            u8 column = (GetBit<6>(b,2) << 3) |
                        (GetBit<6>(b,3) << 2) | 
                        (GetBit<6>(b,4) << 1) | 
                        (GetBit<6>(b,5));

            u32 res = 0;
            switch (s) {
                case 0: res = SP1[row * 16 + column]; break;
                case 1: res = SP2[row * 16 + column]; break;
                case 2: res = SP3[row * 16 + column]; break;
                case 3: res = SP4[row * 16 + column]; break;
                case 4: res = SP5[row * 16 + column]; break;
                case 5: res = SP6[row * 16 + column]; break;
                case 6: res = SP7[row * 16 + column]; break;
                case 7: res = SP8[row * 16 + column]; break;
            }
            b_s |= std::bitset<32>(res);
        }

        // SWAP
        std::bitset<32> new_left = b_s ^ left;
        left = right;
        right = new_left;
    }
    return std::bitset<64>(( right.to_ullong()<< 32) | left.to_ullong());
}

void ReverseKeys(std::bitset<48>* cookeys, int rounds = 16) {
    for (int i = 0; i < rounds / 2; i++) {
        std::bitset<48> temp = cookeys[i];
        cookeys[i] = cookeys[rounds - 1 - i];
        cookeys[rounds - 1 - i] = temp;
    }
}

int main(){
    std::bitset<56> key(0x0E329232EA6D0D73);  

    std::bitset<48>* cookeys = CooKeys(key);

    std::cout << "Key: " << std::hex << cookeys[0].to_ullong() << std::endl;

    std::bitset<64> plaintext(0x012345678922CDEF);
    std::cout << "Plain Text: " << std::hex << plaintext.to_ullong() << std::endl;

    std::bitset<64> ciphertext;
    clock_t start = clock();
    for (size_t i = 0; i < 100000;i++) {
        ciphertext = DesFunc(plaintext, cookeys);
    }
    clock_t end = clock();

    std::cout << "Encrypted: " << ciphertext.to_ullong() << std::endl;

    ReverseKeys(cookeys);

    std::cout << "Decrypted: " << DesFunc(ciphertext, cookeys).to_ullong() << std::endl;

    delete[] cookeys;

    std::cout << "Time: " << (double) (end - start) / CLOCKS_PER_SEC;

    return 0;
}