//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

#include <iostream>
#include "openfhe.h"
#include <vector>
#include <cmath>

using namespace lbcrypto;


void Convolution_in_CKKS(const std::vector<double>& incomingVector, const std::vector<int64_t>& kernel, int st,int inputsize, int row,int kernelrow) {
 
    lbcrypto::SecurityLevel securityLevel = lbcrypto::HEStd_NotSet;
    uint32_t dcrtBits                     = 59;
    uint32_t ringDim                      = 1 << 8;
    uint32_t batchSize                    = 64;
    lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> parameters;
    uint32_t multDepth = 40;

    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(dcrtBits);
    parameters.SetBatchSize(batchSize);
    parameters.SetSecurityLevel(securityLevel);
    parameters.SetRingDim(ringDim);

    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cc;
    cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    KeyPair keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);
   
    std::vector<int32_t> RotateList;

    int l = (kernelrow-1)/2;    
    for (int i=-l; i<=l; i+=1){
        for(int j=-l; j<=l; j+=1){            
                RotateList.push_back(i*row+j);
        }
    }
    // make center vector l : (kernelrow -1)/2
    // center kernel의 row, column에서의 색칠 된 갯수 : kernel shifting 횟수
    int count = (row - kernelrow+2)/st +1;
    std::vector<double> center(inputsize, 0.0);
    for(int dy = 0; dy < count; dy ++){
            for(int dx = 0; dx < count; dx ++){
                center[row*((l-1)+dy*st) + (l-1) + dx*st] =1.0;
            }
        }
    
    cc->EvalRotateKeyGen(keys.secretKey, RotateList);

    std::vector<double> conv_result(inputsize, 0.0);

    
    Plaintext plaintext1 = cc->MakeCKKSPackedPlaintext(incomingVector);
    Plaintext plaintext2 = cc->MakeCKKSPackedPlaintext(conv_result);
    Plaintext plaintext3 = cc->MakeCKKSPackedPlaintext(center);

    auto ct1             = cc->Encrypt(keys.publicKey, plaintext1);
    auto Res            = cc->Encrypt(keys.publicKey, plaintext2);
    auto cen             = cc->Encrypt(keys.publicKey, plaintext3);
   

    
    for(std::vector<int>::size_type i = 0; i<RotateList.size(); i++){
        std::vector<double> temp = center;
        int row_padding = i/kernelrow;
        int column_padding = i%kernelrow;

        if(row_padding < l){
            for(int i =0; i<l-row_padding; i++){
                for(int j =0; j<row; j++){
                    temp[i*row+j]=0.0;
                }
            }
        }
        else if(row_padding >l){
            for(int i =l-row_padding; i<0; i++){
                for(int j =0; j<row; j++){
                    temp[(row+i)*row+j]=0.0;
                }
            }
        }
        if(column_padding < l){
            for(int i =0; i<row; i++){
                for(int j =0; j<l-column_padding; j++){
                    temp[i*row+j]=0.0;
                }
            }
        }
        else if(column_padding >l){
            for(int i =0; i<row; i++){
                for(int j =l-column_padding; j<0; j++){
                    temp[(i+1)*row+j]=0.0;
                }
            }
        }
        

        Plaintext kern = cc->MakeCKKSPackedPlaintext(temp);
        auto res1 = cc->EvalMult(kernel[i],cc->EvalMult(kern, cen));
        auto rot = cc->EvalRotate(ct1, RotateList[i]);
        Res = cc->EvalAdd(Res, cc->EvalMult(rot,res1));
    }

    Plaintext result;
    std::cout.precision(5);
    cc->Decrypt(Res, keys.secretKey, &result);
    result->SetLength(batchSize);
    std::cout << "result : " << *result << std::endl;

}
 
int main(int argc, char* argv[]) {
    std::vector<int64_t> vec = {1, 1, 1, 1, 1, 1, 1, 1, 
                                1, 1, 1, 1, 1, 1, 1, 1,
                                1, 1, 1, 1, 1, 1, 1, 1,
                                1, 1, 1, 1, 1, 1, 1, 1,
                                1, 1, 1, 1, 1, 1, 1, 1,
                                1, 1, 1, 1, 1, 1, 1, 1,
                                1, 1, 1, 1, 1, 1, 1, 1,
                                1, 1, 1, 1, 1, 1, 1, 1};

    std::vector<int64_t> kernel = {1,1,1,
                                   1,1,1,
                                   1,1,1};

    std::vector<double> inputDouble(vec.begin(), vec.end());
    
    int st1 = 1;
    int st2 = 2;

    int inputsize = vec.size();
    int kernelsize = kernel.size();

    int row = sqrt(inputsize);
    int kernelrow = sqrt(kernelsize);

    std:: cout << "stride = 1" << std::endl;
    Convolution_in_CKKS(inputDouble, kernel, st1,inputsize, row, kernelrow);
    std ::cout << std ::endl;
    std ::cout << "stride = 2" << std::endl;
    Convolution_in_CKKS(inputDouble, kernel, st2,inputsize, row, kernelrow);

    return 0;
}
 