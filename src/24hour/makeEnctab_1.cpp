//202110
//There are 12 tables
#include "sg_simulation.hpp"
//Attention: Because we need to rotate the query, just use half of slot!
using namespace std;
using namespace seal;
unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
std::mt19937 generator(seed);

void out_vector(const vector<int64_t> &a){
  for(int j=0 ; j<a.size() ; j++){
    cout<<a[j]<<" ";
  }
  cout<<endl;
}
void show_memory_usage(pid_t pid){ //for Linux
  ostringstream path;
  path << "/proc/" << pid << "/status";
  ostringstream cmd;
  cmd << "grep -e 'VmHWM' -e 'VmSize' -e 'VmStk' -e 'VmData' -e 'VmExe' "<<path.str();
  system(cmd.str().c_str());
  return;
}

int main(int argc, char const *argv[]) {
  auto startWhole=chrono::high_resolution_clock::now();
  //resetting FHE
  cout << "Setting FHE" << endl;
  ifstream parmsFile("Key/Params");
  EncryptionParameters parms(scheme_type::BFV);
  parms = EncryptionParameters::Load(parmsFile);
  auto context = SEALContext::Create(parms);
  parmsFile.close();

  ifstream pkFile("Key/PublicKey");
  PublicKey public_key;
  public_key.unsafe_load(pkFile);
  pkFile.close();

  ifstream relinFile("Key/RelinKey");
  RelinKeys relin_keys16;
  relin_keys16.unsafe_load(relinFile);
  relinFile.close();

  Encryptor encryptor(context, public_key);
  Evaluator evaluator(context);

  BatchEncoder batch_encoder(context);
  IntegerEncoder encoder(context);
  size_t slot_count = batch_encoder.slot_count();
  int64_t row_size = slot_count/2;

  //make tables for ArithmeticMean and HarmonicMean
  //InputTable
  double precision=pow(2,5);
  double precision2=pow(2,8);
  double precision3=pow(2,10);
  cout<<"precision="<<precision<<endl;

  cout<<"////////////////////////////"<<endl;
  cout<<"inputArith, from "<< precision * METER_NUM * log(52)<<" to "<< precision * METER_NUM * log(6002)<<"."<<endl;

  vector<int64_t> inputArith;
  int num1=0;

  for(int64_t i = precision * METER_NUM * log(52) ; i < precision * METER_NUM * log(6002) ; ++i){//从小到大
      inputArith.push_back(i);
      // cout<<"\033[31m input:"<<i<<"  \033[0m";
      num1++;
  }

  cout<<"inputArith table size is:"<<num1<<endl;
  cout<<"inputHarm, from "<< precision3 * METER_NUM / log(52)<<" to "<< precision3 * METER_NUM / log(6002)<<"."<<endl;
  //InputTable
  vector<int64_t> inputHarm;
  int num2=0;
  // cout<<"table2 input, from "<<precision * METER_NUM / log(52)<<" to "<<precision * METER_NUM / log(6002)<<endl;
  for(int64_t j = precision3 * METER_NUM / log(52) ; j > precision3 * METER_NUM / log(6002) ; --j){ //从大到小
      inputHarm.push_back(j);
      // cout<<"\033[34m input:"<<j<<"  \033[0m";
      num2++;
  }
  cout<<"inputHarm table size is:"<<num2<<endl;

  //OutputTable AM and HM
  vector<int64_t> HM_part, AM_part;

  int64_t num3=0,num4=0,distinhm=0,distinam=0;
  double maxhm=0.0, minhm=1000.0, temphm=0.0, maxam=0.0, minam=1000.0, tempam=0.0;

  for(int64_t i=0 ; i<inputArith.size() ; i++){

      double temp_Ar = inputArith[i]/precision;
      double temps_AM = pow(2,9) * (temp_Ar / METER_NUM);//precision
      double temps_AM_real = (temp_Ar / METER_NUM);
      int64_t temps_AM_INT=(int64_t)temps_AM;
      if(abs(temps_AM-temps_AM_INT)>=0.5) temps_AM_INT+=1;
      // cout<<"\033[32m AM in:"<<inputArith[i]<<", AM out: "<<temps_AM_INT<<" \033[0m"<<endl;
      AM_part.push_back(temps_AM_INT);

      if(temps_AM_real>=maxam) maxam=temps_AM_real;
      if(temps_AM_real<=minam) minam=temps_AM_real;
      if(temps_AM_INT!=tempam){ distinam++; tempam=temps_AM_INT; }
      num3++;
  }
  cout<<endl;

  for(int64_t j=0 ; j<inputHarm.size() ; j++){
    double temp_Ha = inputHarm[j]/precision3;
    double temps_HM = pow(2,9) * (METER_NUM / temp_Ha);//precision
    int64_t temps_HM_INT=(int64_t)temps_HM;
    if(abs(temps_HM-temps_HM_INT)>=0.5) temps_HM_INT+=1;
    HM_part.push_back(temps_HM_INT);
    // cout<<"\033[32m HM in:"<<inputHarm[j]<<", HM out:"<<temps_HM_INT<<" \033[0m"<<endl;

    if(temps_HM_INT>=maxhm) maxhm=temps_HM_INT;
    if(temps_HM_INT<=minhm) minhm=temps_HM_INT;
    if(temps_HM_INT!=temphm){ distinhm++; temphm=temps_HM_INT; }
    num4++;
  }
  cout<<"HM input from "<<inputHarm[0]<<" to "<<inputHarm[inputHarm.size()-1]<<endl;
  cout<<"HM output from "<<HM_part[0]<<" to "<<HM_part[HM_part.size()-1]<<endl;
  // cout<<"Max HM:"<<maxhm<<", Min HM:"<<minhm<<", distin HM "<<distinhm<<endl;
  // cout<<"Max real AM "<<maxam<<", Min real HM:"<<minam<<", distin AM "<<distinam<<endl;
  cout<<"-----"<<endl;
  cout<<"AM input from "<<inputArith[0]<<" to "<<inputArith[inputArith.size()-1]<<endl;
  cout<<"AM output from "<<AM_part[0]<<" to "<<AM_part[AM_part.size()-1]<<endl;
  // cout<<"Max AM "<<maxam*METER_NUM<<", Min AM:"<<minam*METER_NUM<<endl;
  cout<<"AM out size:"<<inputArith.size()<<", HM out size:"<<inputHarm.size()<<endl;

  //input/output table of 1/sumAM
  //input sumAM: total of 24hours' AM
  //output 1/sumAM
  vector<int64_t> sum_AM_in, sum_AM_out;
  // double maxra=0.0,minra=10000.0;
  for(int64_t i = AM_part[0] * 24 ; i<=AM_part[AM_part.size()-1] * 24 ; i++){
    sum_AM_in.push_back(i);
    double sum_AM_outnum = pow(2,21) / (i/pow(2,9));
    // cout<<sum_AM_outnum<<endl;
    int64_t sum_AM_outnum_INT=(int64_t)sum_AM_outnum;
    if(sum_AM_outnum-sum_AM_outnum_INT>=0.5) sum_AM_outnum_INT+=1;
    sum_AM_out.push_back(sum_AM_outnum_INT);
    // cout<<"LOOK, 1/sumAM input:"<<i<<", output:"<<sum_AM_outnum_INT<<endl;
    // if(sum_AM_outnum_INT>=maxra) maxra=sum_AM_outnum_INT;
    // if(sum_AM_outnum_INT<=minra) minra=sum_AM_outnum_INT;
  }
  cout<<"-----"<<endl;
  cout<<"input 1/sam from "<<sum_AM_in[0]<<" to "<<sum_AM_in[sum_AM_in.size()-1]<<endl;
  cout<<"output 1/sam from "<<sum_AM_out[0]<<" to "<<sum_AM_out[sum_AM_out.size()-1]<<endl;

  // cout<<"input 1/sam:"<<minam * precision2 * 24<<" to "<<maxam * precision2 * 24 <<endl;
  // cout<<"Max 1/SAM:"<<maxra<<", Min 1/SAM:"<<minra<<endl;
  cout<<"Size:"<<sum_AM_in.size()<<endl;

//////sumHM divide it
  //input sumHM: total of 24hours' HM
  //output sumHM: just divide as two tables, sumHM = HM1 * 100 + HM2
  //because in fact, input and output as same, just one vector. Divide when save table.
  vector<int64_t> sum_HM_inout;
  for(int64_t i = HM_part[0] * 24 ; i<=HM_part[HM_part.size()-1] * 24 ; i++){
    sum_HM_inout.push_back(i);
    // cout<<i<<endl;
  }
  cout<<"-----"<<endl;
  cout<<"input 1/shm from "<<sum_HM_inout[0]<<" to "<<sum_HM_inout[sum_HM_inout.size()-1]<<endl;
  cout<<"Size:"<<sum_HM_inout.size()<<endl;

////////////////////////////////////////////////////////////////////////////
//Save table
//input AM
  ofstream arith_in;
  arith_in.open("Table/AM_input_"+to_string(METER_NUM), ios::binary);

  int64_t row_ar=ceil(double(inputArith.size())/double(row_size));

  vector<int64_t> inputArith_row;
  for(int64_t s=0 ; s<row_ar ; s++){
    for(int64_t k=0 ; k<row_size; k++){
      if((s*row_size+k)<inputArith.size()){
        inputArith_row.push_back(inputArith[s*row_size+k]);
      }else{
        inputArith_row.push_back(50000);
      }
    }
    inputArith_row.resize(slot_count);

    Plaintext temp_pla_ina;
    Ciphertext temp_enc_ina;
    batch_encoder.encode(inputArith_row, temp_pla_ina);
    encryptor.encrypt(temp_pla_ina, temp_enc_ina);
    temp_enc_ina.save(arith_in);
    inputArith_row.clear();

  }
  arith_in.close();

//input HM
  ofstream harm_in;
  harm_in.open("Table/HM_input_"+to_string(METER_NUM), ios::binary);
  int64_t row_ha=ceil(double(inputHarm.size())/double(row_size));
  // cout<<"Harmonic row num:"<<row_ha<<endl;
  vector<int64_t> inputHarm_row;
  for(int64_t s=0 ; s<row_ha ; s++){
    for(int64_t k=0 ; k<row_size; k++){
      if((s*row_size+k)<inputHarm.size()){
        inputHarm_row.push_back(inputHarm[s*row_size+k]);
      }else{
        inputHarm_row.push_back(10000);
      }
    }
    inputHarm_row.resize(slot_count);

    Plaintext temp_pla_inh;
    Ciphertext temp_enc_inh;
    batch_encoder.encode(inputHarm_row, temp_pla_inh);
    encryptor.encrypt(temp_pla_inh, temp_enc_inh);
    temp_enc_inh.save(harm_in);
    inputHarm_row.clear();
  }
  harm_in.close();

//output AM
  ofstream arith_out;
  arith_out.open("Table/AM_output_"+to_string(METER_NUM), ios::binary);

  int64_t row_arout=ceil(double(AM_part.size())/double(row_size));
  vector<int64_t> outputArith_row;
  for(int64_t s=0 ; s<row_arout ; s++){
    for(int64_t k=0 ; k<row_size; k++){
      if((s*row_size+k)<AM_part.size()){
        outputArith_row.push_back(AM_part[s*row_size+k]);
      }else{
        outputArith_row.push_back(500);
      }
    }
    outputArith_row.resize(slot_count);

    Plaintext temp_pla_outa;
    Ciphertext temp_enc_outa;
    batch_encoder.encode(outputArith_row, temp_pla_outa);
    encryptor.encrypt(temp_pla_outa, temp_enc_outa);
    temp_enc_outa.save(arith_out);
    outputArith_row.clear();
  }
  arith_out.close();

//output HM
  ofstream h_out;
  h_out.open("Table/HM_output_"+to_string(METER_NUM), ios::binary);

  int64_t row_hout=ceil(double(HM_part.size())/double(row_size));
  vector<int64_t> outputh_row;
  for(int64_t s=0 ; s<row_hout ; s++){
    for(int64_t k=0 ; k<row_size; k++){
      if((s*row_size+k)<HM_part.size()){
        outputh_row.push_back(HM_part[s*row_size+k]);
      }else{
        outputh_row.push_back(500);
      }
    }
    outputh_row.resize(slot_count);

    Plaintext temp_pla_outh;
    Ciphertext temp_enc_outh;
    batch_encoder.encode(outputh_row, temp_pla_outh);
    encryptor.encrypt(temp_pla_outh, temp_enc_outh);
    temp_enc_outh.save(h_out);
    outputh_row.clear();
  }
  h_out.close();

//sumHM input
  ofstream sumhm_in;
  sumhm_in.open("Table/div_HM_input_"+to_string(METER_NUM), ios::binary);
  int64_t row_sumhin=ceil(double(sum_HM_inout.size())/double(row_size));
  // cout<<"Harmonic row num:"<<row_ha<<endl;
  vector<int64_t> inputSumH_row;
  for(int64_t s=0 ; s<row_sumhin ; s++){
    for(int64_t k=0 ; k<row_size; k++){
      if((s*row_size+k)<sum_HM_inout.size()){
        inputSumH_row.push_back(sum_HM_inout[s*row_size+k]);
      }else{
        inputSumH_row.push_back(60000);
      }
    }
    inputSumH_row.resize(slot_count);

    Plaintext temp_pla_sumh;
    Ciphertext temp_enc_sumh;
    batch_encoder.encode(inputSumH_row, temp_pla_sumh);
    encryptor.encrypt(temp_pla_sumh, temp_enc_sumh);
    temp_enc_sumh.save(sumhm_in);
    inputSumH_row.clear();
  }
  sumhm_in.close();

//sumHM output divided part
  int64_t HM1_max=0, HM1_min=1000, HM2_max=0, HM2_min=1000;

  ofstream harm_out1;
  harm_out1.open("Table/div_HM_output1_"+to_string(METER_NUM), ios::binary);
  ofstream harm_out2;
  harm_out2.open("Table/div_HM_output2_"+to_string(METER_NUM), ios::binary);
  int64_t row_haout=ceil(double(sum_HM_inout.size())/double(row_size));
  // cout<<"Harmonic row num:"<<row_ha<<endl;
  cout<<"Divided HM output table."<<endl;
  vector<int64_t> outputHarm_row1,outputHarm_row2;
  for(int64_t s=0 ; s<row_haout ; s++){
    for(int64_t k=0 ; k<row_size; k++){
      if((s*row_size+k)<sum_HM_inout.size()){
        outputHarm_row1.push_back(sum_HM_inout[s*row_size+k]/100);
        outputHarm_row2.push_back(sum_HM_inout[s*row_size+k]%100);
        // cout<<"here1:"<<sum_HM_inout[s*row_size+k]/100<<", here2:"<<sum_HM_inout[s*row_size+k]%100<<endl;
        if((sum_HM_inout[s*row_size+k]/100)>HM1_max) HM1_max=(sum_HM_inout[s*row_size+k]/100);
        if((sum_HM_inout[s*row_size+k]/100)<HM1_min) HM1_min=(sum_HM_inout[s*row_size+k]/100);
        if((sum_HM_inout[s*row_size+k]%100)>HM2_max) HM2_max=(sum_HM_inout[s*row_size+k]%100);
        if((sum_HM_inout[s*row_size+k]%100)<HM2_min) HM2_min=(sum_HM_inout[s*row_size+k]%100);
      }else{
        outputHarm_row1.push_back(600);
        outputHarm_row2.push_back(1);
      }
    }
    outputHarm_row1.resize(slot_count);
    outputHarm_row2.resize(slot_count);

    Plaintext temp_pla_outh1,temp_pla_outh2;
    Ciphertext temp_enc_outh1,temp_enc_outh2;
    batch_encoder.encode(outputHarm_row1, temp_pla_outh1);
    encryptor.encrypt(temp_pla_outh1, temp_enc_outh1);
    temp_enc_outh1.save(harm_out1);
    outputHarm_row1.clear();
    batch_encoder.encode(outputHarm_row2, temp_pla_outh2);
    encryptor.encrypt(temp_pla_outh2, temp_enc_outh2);
    temp_enc_outh2.save(harm_out2);
    outputHarm_row2.clear();
  }
  harm_out1.close();
  harm_out2.close();

//sum_AM InputTable
  ofstream sumam_in;
  sumam_in.open("Table/SUM_AM_input_"+to_string(METER_NUM), ios::binary);
  int64_t row_sumain=ceil(double(sum_AM_in.size())/double(row_size));
  // cout<<"Harmonic row num:"<<row_ha<<endl;
  vector<int64_t> inputSumA_row;
  for(int64_t s=0 ; s<row_sumain ; s++){
    for(int64_t k=0 ; k<row_size; k++){
      if((s*row_size+k)<sum_AM_in.size()){
        inputSumA_row.push_back(sum_AM_in[s*row_size+k]);
      }else{
        inputSumA_row.push_back(60000);
      }
    }
    inputSumA_row.resize(slot_count);

    Plaintext temp_pla_suma;
    Ciphertext temp_enc_suma;
    batch_encoder.encode(inputSumA_row, temp_pla_suma);
    encryptor.encrypt(temp_pla_suma, temp_enc_suma);
    temp_enc_suma.save(sumam_in);
    inputSumA_row.clear();
  }
  sumam_in.close();
//
//1/sum_AM OutputTable
  int64_t AM1_max=0, AM1_min=100, AM2_max=0, AM2_min=100;
  ofstream lnv_am_out1;
  lnv_am_out1.open("Table/inv_SUM_AM_output1_"+to_string(METER_NUM), ios::binary);
  ofstream lnv_am_out2;
  lnv_am_out2.open("Table/inv_SUM_AM_output2_"+to_string(METER_NUM), ios::binary);
  int64_t row_sumaout=ceil(double(sum_AM_out.size())/double(row_size));
  // cout<<"Harmonic row num:"<<row_ha<<endl;
  vector<int64_t> inputSumA_row1,inputSumA_row2;
  for(int64_t s=0 ; s<row_sumaout ; s++){
    for(int64_t k=0 ; k<row_size; k++){
      if((s*row_size+k)<sum_AM_out.size()){
        inputSumA_row1.push_back(sum_AM_out[s*row_size+k]/100);
        inputSumA_row2.push_back(sum_AM_out[s*row_size+k]%100);
        // cout<<"part1:"<<sum_AM_out[s*row_size+k]/100<<", part2:"<<sum_AM_out[s*row_size+k]%100<<endl;
        if((sum_AM_out[s*row_size+k]/100)>AM1_max) AM1_max=(sum_AM_out[s*row_size+k]/100);
        if((sum_AM_out[s*row_size+k]/100)<AM1_min) AM1_min=(sum_AM_out[s*row_size+k]/100);
        if((sum_AM_out[s*row_size+k]%100)>AM2_max) AM2_max=(sum_AM_out[s*row_size+k]%100);
        if((sum_AM_out[s*row_size+k]%100)<AM2_min) AM2_min=(sum_AM_out[s*row_size+k]%100);
      }else{
        inputSumA_row1.push_back(1);
        inputSumA_row2.push_back(1);
      }
    }
    inputSumA_row1.resize(slot_count);
    inputSumA_row2.resize(slot_count);

    Plaintext temp_pla_suma1,temp_pla_suma2;
    Ciphertext temp_enc_suma1,temp_enc_suma2;
    batch_encoder.encode(inputSumA_row1, temp_pla_suma1);
    encryptor.encrypt(temp_pla_suma1, temp_enc_suma1);
    temp_enc_suma1.save(lnv_am_out1);
    inputSumA_row1.clear();
    batch_encoder.encode(inputSumA_row2, temp_pla_suma2);
    encryptor.encrypt(temp_pla_suma2, temp_enc_suma2);
    temp_enc_suma2.save(lnv_am_out2);
    inputSumA_row2.clear();
  }
  lnv_am_out1.close();
  lnv_am_out2.close();

// here add one table for N/100
  cout<<"HM1_max:"<<HM1_max<<", HM1_min:"<<HM1_min<<", HM2_max:"<<HM2_max<<", HM2_min:"<<HM2_min<<endl;
  cout<<"AM1_max:"<<AM1_max<<", AM1_min:"<<AM1_min<<", AM2_max:"<<AM2_max<<", AM2_min:"<<AM2_min<<endl;
  vector<int64_t> inv_in, inv_out;//(HM1*AM2+HM2*AM1)
  int64_t inv_max=HM1_max*AM2_max+HM2_max*AM1_max;
  int64_t inv_min=HM1_min*AM2_min+HM2_min*AM1_min;

  for(int64_t i =inv_min ; i<=inv_max ; i++){
    inv_in.push_back(i);
    double ttd=i/100.0;
    int64_t tti=i/100;
    // cout<<"ttd"<<ttd<<",tti "<<tti<<endl;
    if(ttd-tti>=0.5) inv_out.push_back(tti+1);
    else inv_out.push_back(tti);
  }
  cout<<"-----"<<endl;
  cout<<"inv100 size:"<<inv_in.size()<<endl;
  cout<<"input inv from "<<inv_in[0]<<" to "<<inv_in[inv_in.size()-1]<<endl;
  cout<<"output inv from "<<inv_out[0]<<" to "<<inv_out[inv_out.size()-1]<<endl;


  ofstream lnv_100_in;
  lnv_100_in.open("Table/inv_100_input_"+to_string(METER_NUM), ios::binary);
  ofstream lnv_100_out;
  lnv_100_out.open("Table/inv_100_output_"+to_string(METER_NUM), ios::binary);
  int64_t row_100in=ceil(double(inv_in.size())/double(row_size));
  // cout<<"Harmonic row num:"<<row_ha<<endl;
  vector<int64_t> input100_row,output100_row;
  for(int64_t s=0 ; s<row_100in ; s++){
    for(int64_t k=0 ; k<row_size; k++){
      if((s*row_size+k)<inv_in.size()){
        input100_row.push_back(inv_in[s*row_size+k]);
        output100_row.push_back(inv_out[s*row_size+k]);
        // cout<<"in:"<<inv_in[s*row_size+k]<<", out:"<<inv_out[s*row_size+k]<<endl;
      }else{
        input100_row.push_back(60000);
        output100_row.push_back(1);
      }
    }
    input100_row.resize(slot_count);
    output100_row.resize(slot_count);

    Plaintext temp_pla_100in,temp_pla_100out;
    Ciphertext temp_enc_100in,temp_enc_100out;
    batch_encoder.encode(input100_row, temp_pla_100in);
    encryptor.encrypt(temp_pla_100in, temp_enc_100in);
    temp_enc_100in.save(lnv_100_in);
    input100_row.clear();

    batch_encoder.encode(output100_row, temp_pla_100out);
    encryptor.encrypt(temp_pla_100out, temp_enc_100out);
    temp_enc_100out.save(lnv_100_out);
    output100_row.clear();
  }
  lnv_100_in.close();
  lnv_100_out.close();


  auto endWhole=chrono::high_resolution_clock::now();
  chrono::duration<double> diffWhole = endWhole-startWhole;
  cout << "Whole runtime is: " << diffWhole.count() << "s" << endl;
  show_memory_usage(getpid());
  return 0;
}
