#include <iostream>
#include <bitset>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <string>
#include <fstream>
#include "tables.cpp"
using namespace std;

class DES{
private:
    vector<bitset<48>> keys;
    bitset<64> text_to_bitset(const string &text){
        bitset<64> block;
        for(int i=0;i<8;i++){
            unsigned char c=text[i];
            for(int j=0;j<8;j++){
                block[63-(i*8+j)]=(c>>(7-j))&1;
            }
        }
        return block;
    }

    string bitset_to_text(const bitset<64> &block){
        string text;
        text.reserve(8);
        for(int i=0;i<8;i++){
            unsigned char c=0;
            for(int j=0;j<8;j++){
                c|=(block[63-(i*8+j)]<<(7-j));
            }
            text.push_back(c);
        }
        return text;
    }

    template<size_t N,size_t M>
    bitset<N> p_box(const bitset<M> &input, const int table[]){
        bitset<N> output;
        for(int i=0;i<int(N);i++){
            output[N-1-i]=input[M-table[i]];
        }
        return output;
    }

    pair<bitset<32>,bitset<32>> block_split(const bitset<64> &x64 ){
        bitset<32> L;
        bitset<32>R;
        for(int i=0;i<32;++i){
            L[i]=x64[i];
            R[i]=x64[i+32];
        }
        return {L,R};
    }

    pair<bitset<28>,bitset<28>> round_key_gen_split(const bitset<64> &key){
        bitset<56> r_key=p_box<56,64>(key,PC1);
        bitset<28> C;
        bitset<28> D;
        for(int i=0;i<28;++i){
            C[i]=r_key[i];
            D[i]=r_key[i+28];
        }
        return {C,D};
    }

    bitset<28> left_shift(const bitset<28> &half, int shift){
        shift%=28;
        bitset<28> res;
        for (int i=0;i<28;i++) {
            res[i]=half[(i+shift)%28];
        }
        return res;
    }

    bitset<56> merge_halves(const bitset<28> &C, const bitset<28> &D){
        bitset<56> output;
        for (int i=0;i<28;i++) {
            output[i]=C[i];
            output[28+i]=D[i];
        }
        return output;
    }

    void round_key_store(const string &key, bool rev=false){
        keys.clear();
        bitset<64> x64_key=text_to_bitset(key);
        pair<bitset<28>,bitset<28>>CD=round_key_gen_split(x64_key);
        bitset<28> C=CD.first;
        bitset<28> D=CD.second;
        for (int i=0;i<16;i++){
            C = left_shift(C,shift[i]);
            D = left_shift(D,shift[i]);
            bitset<56> merged=merge_halves(C,D);
            keys.push_back(p_box<48,56>(merged,PC2));
        }
        if (rev) {
            reverse(keys.begin(), keys.end());
        }
    }

    bitset<32> s_box(const bitset<48> &input){
        bitset<32> output;
        int x=0;
        for(int i=0;i<8;i++){
            bitset<6> six_bits;
            for(int j=0;j<6;j++){
                six_bits[5-j]=input[i*6+j];
            }
            int row=(six_bits[5]<<1) | six_bits[0];
            int col=(six_bits[4]<<3) | (six_bits[3]<<2) | (six_bits[2]<<1) | six_bits[1];
            int value=S[i][row][col];
            bitset<4> sub_value(value);
            for(int k=3;k>=0;k--,x++){
                output[x]=sub_value[k];
            }
        }
        return output;
    }

public:
    DES() {}

    string encrypt(const string &plaintext, const string &key){
        bitset<64> msg=text_to_bitset(plaintext);
        round_key_store(key);
        msg=p_box<64,64>(msg,IP);
        auto LR= block_split(msg);
        bitset<32> L0=LR.first,R0=LR.second;
        for(int i=0;i<16;i++){
            bitset<32> temp=R0;
            bitset<48> R_expanded=p_box<48,32>(R0,E);
            bitset<48> XOR_result=R_expanded^keys[i];
            bitset<32> result=s_box(XOR_result);
            bitset<32> p_result=p_box<32,32>(result,P);
            R0=L0^p_result;
            L0=temp;
        }
        bitset<64> cipherblock;
        for(int i=0;i<32;i++){
            cipherblock[i]=R0[i];
            cipherblock[i+32]=L0[i];
        }
        cipherblock=p_box<64,64>(cipherblock,FP);
        string ciphertext=bitset_to_text(cipherblock);
        return ciphertext;
    }

    string decrypt(const string &ciphertext, const string &key){
        bitset<64> secret_msg=text_to_bitset(ciphertext);
        round_key_store(key,true);
        secret_msg=p_box<64,64>(secret_msg,IP);
        auto LR=block_split(secret_msg);
        bitset<32> L0=LR.first, R0=LR.second;
        for(int i=0;i<16;i++){
            bitset<32> temp=R0;
            bitset<48> R_expanded=p_box<48,32>(R0,E);
            bitset<48> XOR_result=R_expanded^keys[i];
            bitset<32> result=s_box(XOR_result);
            bitset<32> p_result=p_box<32,32>(result,P);
            R0=L0^p_result;
            L0=temp;
        }
        bitset<64> plaintext_block;
        for(int i=0;i<32;i++){
            plaintext_block[i]=R0[i];
            plaintext_block[i+32]=L0[i];
        }
        plaintext_block=p_box<64,64>(plaintext_block,FP);
        string plaintext=bitset_to_text(plaintext_block);
        return plaintext;
    }

    string CBC_CTS_encrypt(const string &plaintext, const string &key){
        const unsigned long long bsz=8ULL;
        string ciphertext;
        string prev="12345678"; // Example IV, should be random in practice
        if (plaintext.empty()){
            return ciphertext;
        }
        unsigned long long full_len=(plaintext.size()/bsz)*bsz;
        unsigned long long d=plaintext.size()-full_len;
        if(d==0){
            for(unsigned long long i=0;i<plaintext.size();i+=bsz){
                string block=plaintext.substr(i,bsz);
                string x;
                x.reserve(bsz);
                for(unsigned long long j=0;j<bsz;++j) x.push_back(block[j]^prev[j]);
                string c=encrypt(x,key);
                ciphertext+=c;
                prev=c;
            }
            return ciphertext;
        }
        if(full_len==0){
            string block=plaintext+string(bsz-d,'\0');
            string x;
            x.reserve(bsz);
            for(unsigned long long j=0;j<bsz;++j) x.push_back(block[j]^prev[j]);
            string c=encrypt(x,key);
            ciphertext+=c;
            return ciphertext;
        }
        unsigned long long upto=full_len -bsz;
        for(unsigned long long i=0;i<upto;i+=bsz){
            string block=plaintext.substr(i,bsz);
            string x;x.reserve(bsz);
            for(unsigned long long j=0;j<bsz;++j) x.push_back(block[j]^prev[j]);
            string c=encrypt(x,key);
            ciphertext+=c;
            prev=c;
        }
        string Pn_1=plaintext.substr(full_len-bsz,bsz);
        string Pn_star=plaintext.substr(full_len);
        string Pn=Pn_star+string(bsz-d,'\0');
        string x1;
        x1.reserve(bsz);
        for(unsigned long long j=0;j<bsz;++j)x1.push_back(Pn_1[j]^prev[j]);
        string Cn_1=encrypt(x1,key);
        string x2;
        x2.reserve(bsz);
        for(unsigned long long j=0;j<bsz;++j) x2.push_back(Pn[j]^Cn_1[j]);
        string Cn=encrypt(x2,key);
        ciphertext+=Cn_1.substr(0,d);
        ciphertext+=Cn;
        return ciphertext;
    }

    // decrypt ciphertext produced by CBC_CTS_encrypt (IV hardcoded to "12345678" here to match encrypt)
string CBC_CTS_decrypt(const string &ciphertext, const string &key) {
    const unsigned long long bsz = 8ULL;
    if (ciphertext.empty()) return string();

    // ciphertext length equals original plaintext length in this CBC-CTS implementation
    unsigned long long plaintext_len = ciphertext.size();

    string plaintext;
    plaintext.reserve(plaintext_len);

    string prev = "12345678"; // must match encryption IV (change if you used a different IV)

    unsigned long long d = plaintext_len % bsz;
    if (d == 0) {
        // full-block case
        for (unsigned long long i = 0; i < ciphertext.size(); i += bsz) {
            string C = ciphertext.substr(i, bsz);
            string D = decrypt(C, key);
            string P;
            P.reserve(bsz);
            for (unsigned long long j = 0; j < bsz; ++j) P.push_back(D[j] ^ prev[j]);
            plaintext += P;
            prev = C;
        }
        return plaintext;
    }

    // partial last block (CTS) case
    if (ciphertext.size() < (bsz + d)) {
        // extremely small ciphertext (single partial block)
        string C = ciphertext.substr(0, bsz);
        string D = decrypt(C, key);
        string P;
        P.reserve(bsz);
        for (unsigned long long j = 0; j < bsz; ++j) P.push_back(D[j] ^ prev[j]);
        return P.substr(0, plaintext_len);
    }

    unsigned long long pre_len = ciphertext.size() - (bsz + d);
    // decrypt all full blocks except final two that are handled by CTS
    for (unsigned long long i = 0; i < pre_len; i += bsz) {
        string C = ciphertext.substr(i, bsz);
        string D = decrypt(C, key);
        string P;
        P.reserve(bsz);
        for (unsigned long long j = 0; j < bsz; ++j) P.push_back(D[j] ^ prev[j]);
        plaintext += P;
        prev = C;
    }

    // Now handle the final two-block CTS construction
    string Cn_1_star = ciphertext.substr(pre_len, d);        // d bytes (prefix of C_{n-1})
    string Cn = ciphertext.substr(pre_len + d, bsz);        // full C_n (8 bytes)

    string Z = decrypt(Cn, key);                            // Z = D(Cn)
    string Cn_1 = Cn_1_star + Z.substr(d);                  // reconstruct full C_{n-1}
    string Dn_1 = decrypt(Cn_1, key);                       // D(C_{n-1})

    // P_{n-1} = Dn_1 XOR prev
    string Pn_1;
    Pn_1.reserve(bsz);
    for (unsigned long long j = 0; j < bsz; ++j) Pn_1.push_back(Dn_1[j] ^ prev[j]);

    // Pn* = (Z XOR C_{n-1})[0..d-1]
    string Zn_xor_Cn_1;
    Zn_xor_Cn_1.reserve(bsz);
    for (unsigned long long j = 0; j < bsz; ++j) Zn_xor_Cn_1.push_back(Z[j] ^ Cn_1[j]);
    string Pn_star = Zn_xor_Cn_1.substr(0, d);

    plaintext += Pn_1;
    plaintext += Pn_star;

    // Trim to exact plaintext length (should match ciphertext.size())
    return plaintext.substr(0, plaintext_len);
}

};
   