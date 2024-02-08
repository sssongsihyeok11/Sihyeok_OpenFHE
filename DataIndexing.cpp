#include "openfhe.h"
#include <time.h>

using namespace lbcrypto;

void Data_Indexing(){
    clock_t start, end;
    double Tresult;

    uint32_t batchSize = 8;
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

    KeyPair<DCRTPoly> keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    start = clock();
    // compare a and b
    int a =12;
    int b= 12;

    std::vector<double> x;
    std::vector<double> y;

     while (a > 0 && b > 0 ) {
        int remainder1 = a % 2;
        int remainder2 = b % 2;
        x.insert(x.begin(), remainder1);
        y.insert(y.begin(), remainder2);
        a /= 2;
        b /= 2;
    }

    std::vector<int32_t> indexList;

    int len = x.size();
    while(len>=1){
        len = len/2;
        indexList.push_back(len);    
    }
    cc->EvalRotateKeyGen(keys.secretKey, indexList);

    Plaintext ptxt        = cc->MakeCKKSPackedPlaintext(x);
    Plaintext ptxt1       = cc->MakeCKKSPackedPlaintext(y);

    auto c0 = cc->Encrypt(keys.publicKey, ptxt);
    auto c1 = cc->Encrypt(keys.publicKey, ptxt1);

    //XNOR Gate
    auto c2xy = cc->EvalMult(cc->EvalMult(c0,c1),2);
    auto c_1_x = cc->EvalAdd(1,-c0);
    auto c_1_x_y = cc->EvalAdd(c_1_x,-c1);
    auto c_1_x_y_2xy = cc->EvalAdd(c_1_x_y,c2xy);

    //Rotation
    for(size_t i=0; i<indexList.size(); i++){
        auto rot = cc->EvalRotate(c_1_x_y_2xy,indexList[i]);
        c_1_x_y_2xy = cc->EvalMult(c_1_x_y_2xy,rot);
    }

    Plaintext result;

    cc->Decrypt(keys.secretKey, c_1_x_y_2xy, &result);
    end = clock();
    Tresult = (double)(end-start);

    std::cout << "Result = " << *result << std::endl;
    std::cout << "Time result = " << (double)Tresult/CLOCKS_PER_SEC<< "milisecond" <<std::endl;

}

int main()
{
    Data_Indexing();
}