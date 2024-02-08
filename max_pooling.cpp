#include <iostream>
#include "openfhe.h"
#include <vector>
#include <cmath>
using namespace lbcrypto;

Ciphertext<DCRTPoly> PolySign(Ciphertext<DCRTPoly> ciphertext, CryptoContext<DCRTPoly> cc) {
    Ciphertext<DCRTPoly> Res = ciphertext;
    for (int i = 0; i < 6; i++) {
        Res = cc->EvalAdd(cc->EvalMult(-1.0 / 2, cc->EvalMult(cc->EvalSquare(Res), Res)), cc->EvalMult(3.0 / 2, Res));
    }

    return Res;
}

Ciphertext<DCRTPoly> PolyMax(Ciphertext<DCRTPoly> ciphertext1, Ciphertext<DCRTPoly> ciphertext2, CryptoContext<DCRTPoly> cc) {
    auto C1PlusC2 = cc->EvalAdd(ciphertext1, ciphertext2);
    auto C1MinusC2 = cc->EvalSub(ciphertext1, ciphertext2);
    auto dummy = cc->EvalMult(2 / 3.14, cc->EvalArcTan(C1MinusC2, -1000, 1000, 100));
    auto signResult = cc->EvalMult(C1MinusC2, PolySign(dummy, cc));
    auto result = cc->EvalMult(0.5, cc->EvalAdd(C1PlusC2, signResult));

    return result;
}

void max_pooling() {

    uint32_t batchSize = 16;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(100);
    parameters.SetScalingModSize(50);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
    parameters.SetBatchSize(batchSize);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    KeyPair<DCRTPoly> keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);

    int pooling_size = 4;
    int pooling_row = sqrt(pooling_size);

    std::vector<double> Ex = { -10, 100, 10, 120, 100, -10, 100, 10, 120, 100, -10, 100, 10, 120, 100, -10 };

    int input_size = Ex.size();

    std::vector<double> temp;

    for (int i = 0; i < pooling_size; i++) {
        for (int j = 0; j < pooling_size; j++) {
            if (i % pooling_row == 0 && j % pooling_row == 0) {
                temp.push_back(1.0);
            }
            else
                temp.push_back(0.0);
        }
    }

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

    auto ciphertext1 = cc->Encrypt(keys.publicKey, ptxt);
    auto ct = cc->Encrypt(keys.publicKey, ptxt1);
    auto res1 = cc->Encrypt(keys.publicKey, ptxt2);
    auto res2 = cc->Encrypt(keys.publicKey, ptxt2);

    res1 = cc->EvalAdd(res1, ciphertext1);

    for (size_t i = 0; i < row_RotateList.size(); i++) {
        auto ciphertext2 = cc->EvalRotate(ciphertext1, row_RotateList[i]);
        res1 = PolyMax(res1, ciphertext2, cc);
    }
    res2 = res1;
    for (size_t i = 0; i < index_RotateList.size(); i++) {
        auto ciphertext2 = cc->EvalRotate(res1, index_RotateList[i]);
        res2 = PolyMax(res2, ciphertext2, cc);
    }
    auto Res = cc->EvalMult(res2, ct);

    Plaintext result;
    std::cout.precision(5);
    cc->Decrypt(Res, keys.secretKey, &result);
    result->SetLength(batchSize);
    std::cout << "result : " << *result << std::endl;
}

int main() {
    max_pooling();
}