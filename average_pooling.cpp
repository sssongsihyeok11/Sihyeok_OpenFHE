#include <iostream>
#include "openfhe.h"
#include <vector>
#include <cmath>
using namespace lbcrypto;


void average_pooling() {

    uint32_t batchSize = 128;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(10);
    parameters.SetScalingModSize(50);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    KeyPair keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);

    int pooling_size = 9; //parameter
    int pooling_row = sqrt(pooling_size);

    std::vector<double> temp;

    for (int i = 0; i < pooling_size; i++) {
        for (int j = 0; j < pooling_size; j++) {
            if (i % pooling_row == 0 && j % pooling_row == 0) {
                temp.push_back(1.0 / pooling_size);
            }
            else
                temp.push_back(0.0);
        }
    }

    std::vector<double> Ex(81, 1.0);
    int input_size = Ex.size();
    std::vector<int32_t> row_RotateList;
    std::vector<int32_t> index_RotateList;
    int count = 1;
    while (count < pooling_row) {
        row_RotateList.push_back(count * pooling_size);
        count++;
    }
    for (int i = 1; i < pooling_row; i++) {
        index_RotateList.push_back(i);
    }

    cc->EvalRotateKeyGen(keys.secretKey, row_RotateList);
    cc->EvalRotateKeyGen(keys.secretKey, index_RotateList);

    std::vector<double> Result(input_size, 0.0);
    std::vector<double> Result2(input_size, 0.0);

    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(Ex);
    Plaintext ptxt1 = cc->MakeCKKSPackedPlaintext(temp);
    Plaintext ptxt2 = cc->MakeCKKSPackedPlaintext(Result);
    Plaintext ptxt3 = cc->MakeCKKSPackedPlaintext(Result2);

    auto ciphertext1 = cc->Encrypt(ptxt, keys.publicKey);
    auto ct = cc->Encrypt(ptxt1, keys.publicKey);
    auto res1 = cc->Encrypt(ptxt2, keys.publicKey);
    auto res2 = cc->Encrypt(ptxt2, keys.publicKey);

    res1 = cc->EvalAdd(res1, ciphertext1);

    for (size_t i = 0; i < row_RotateList.size(); i++) {
        auto ciphertext2 = cc->EvalRotate(ciphertext1, row_RotateList[i]);
        res1 = cc->EvalAdd(res1, ciphertext2);
    }

    res2 = res1;
    for (size_t i = 0; i < index_RotateList.size(); i++) {
        auto ciphertext2 = cc->EvalRotate(res1, index_RotateList[i]);
        res2 = cc->EvalAdd(res2, ciphertext2);
    }
    auto Res = cc->EvalMult(res2, ct);

    Plaintext result;
    std::cout.precision(5);
    cc->Decrypt(Res, keys.secretKey, &result);
    result->SetLength(batchSize);
    std::cout << "result : " << *result << std::endl;
}

int main() {
    average_pooling();
}