//201812@Richelle
//୧(๑•̀⌄•́๑)૭✧
#include "sg_simulation.hpp"

using namespace std;
using namespace seal;

void out_vector(const vector<int64_t> &a){
  for(int j=0 ; j<a.size() ; j++){

    if(a[j]!= 0) cout<<"\033[1;33m "<<a[j]<<"\033[0m";
    else cout<<a[j]<<" ";
  }
  cout<<endl;
}
//random seed
unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
std::mt19937 generator(seed);

void show_memory_usage(pid_t pid){ //for Linux
  ostringstream path;
  path << "/proc/" << pid << "/status";
  ostringstream cmd;
  cmd << "grep -e 'VmHWM' -e 'VmSize' -e 'VmStk' -e 'VmData' -e 'VmExe' "<<path.str();
  system(cmd.str().c_str());
  return;
}

//output a plaintext table
void output_plaintext(const vector<vector <int64_t>> &a){
  int64_t row=a.size();
  int64_t col=a[0].size();
  for(int i=0 ; i<row ; i++){
      for(int j=0 ; j<col ; j++)
          cout<<a[i][j]<<" ";
      cout<<endl;
  }
}

int main(int argc, char *argv[]){
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

  ifstream galFile("Key/GaloisKey");
  GaloisKeys gal_keys;
  gal_keys.unsafe_load(galFile);
  galFile.close();

  ifstream relinFile("Key/RelinKey");
  RelinKeys relin_keys16;
  relin_keys16.unsafe_load(relinFile);
  relinFile.close();

///noise budget check
  ifstream skFile("Key/SecretKey");
  SecretKey secret_key;
  secret_key.unsafe_load(skFile);
  skFile.close();
  Decryptor decryptor(context, secret_key);
///
  Encryptor encryptor(context, public_key);
  Evaluator evaluator(context);

  BatchEncoder batch_encoder(context);
  IntegerEncoder encoder(context);
  size_t slot_count = batch_encoder.slot_count();
  size_t row_size = slot_count/2;
  cout << "Plaintext matrix row size: " << slot_count << endl;
  cout << "Slot nums = " << slot_count << endl;

  int64_t sum_row_count_AM=ceil((double)TABLE_SIZE_AM_INV/(double)row_size);
  int64_t inv100_row=ceil((double)TABLE_SIZE_100_INV/(double)row_size);
  int64_t div_row_count_HM=ceil((double)TABLE_SIZE_DIV_HM/(double)row_size);

  vector<Ciphertext> output_HM1, output_HM2;

  ifstream readtablehm_part1;
  readtablehm_part1.open("Table/div_HM_output1_"+to_string(METER_NUM));
  ifstream readtablehm_part2;
  readtablehm_part2.open("Table/div_HM_output2_"+to_string(METER_NUM));
  for(int w = 0; w < div_row_count_HM ; w++) {
    Ciphertext temp1, temp2;
    temp1.load(context, readtablehm_part1);
    temp2.load(context, readtablehm_part2);
    output_HM1.push_back(temp1);
    output_HM2.push_back(temp2);
  }

  vector<Ciphertext> res_h1, res_h2;
  Ciphertext HM_rec1, HM_rec2;
  for(int64_t i=0 ; i<div_row_count_HM ; i++){
    Ciphertext tep;
    res_h1.push_back(tep);
    res_h2.push_back(tep);
  }

    string s1(argv[1]);
    string s2(argv[2]);
////////////////////////////////////////////////////////////////////
    cout<<"=====Main====="<<endl;
    //read index and PIR query from file
    cout << "===Reading query from DS===" << endl;
    ifstream PIRqueryFile(s2+"/pir_DIV_HM_"+s1);
    Ciphertext ct_query_HM0, ct_query_HM1;

    ct_query_HM0.load(context, PIRqueryFile);
    ct_query_HM1.load(context, PIRqueryFile);
    PIRqueryFile.close();
    cout<<"Reading query from DS > OK"<<endl;
    cout<<"LUT Processing"<<endl;

    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int64_t j=0 ; j<div_row_count_HM ; j++){
      Ciphertext temp_h1 = ct_query_HM1;
      Ciphertext temp_h2 = ct_query_HM1;
      evaluator.rotate_rows_inplace(temp_h1, -j, gal_keys);
      evaluator.rotate_rows_inplace(temp_h2, -j, gal_keys);
      evaluator.multiply_inplace(temp_h1, ct_query_HM0);
      evaluator.multiply_inplace(temp_h2, ct_query_HM0);
      evaluator.relinearize_inplace(temp_h1, relin_keys16);
      evaluator.relinearize_inplace(temp_h2, relin_keys16);
      evaluator.multiply_inplace(temp_h1, output_HM1[j]);
      evaluator.multiply_inplace(temp_h2, output_HM2[j]);
      evaluator.relinearize_inplace(temp_h1, relin_keys16);
      evaluator.relinearize_inplace(temp_h2, relin_keys16);
      res_h1[j]=temp_h1;
      res_h2[j]=temp_h2;
    }

    // //result sum
    cout<<"===Sum result==="<<endl;
    HM_rec1 = res_h1[0];
    HM_rec2 = res_h2[0];
    for(int k=1 ; k<div_row_count_HM ; k++){
      evaluator.add_inplace(HM_rec1, res_h1[k]);
      evaluator.add_inplace(HM_rec2, res_h2[k]);
    }
    cout << "Size after relinearization: " << HM_rec1.size() << endl;


     vector<Ciphertext> zz3, zz4;
     for(int64_t ss=0 ; ss<row_size; ss++){
       zz3.push_back(HM_rec1);
       zz4.push_back(HM_rec2);
     }
     Ciphertext ct_HM1 = HM_rec1; //HM_rec1: sum all row
     Ciphertext ct_HM2 = HM_rec2; //HM_rec2: sum all row

     omp_set_num_threads(NF);
     #pragma omp parallel for
     for(int64_t j=1 ; j<row_size ; j++){
       evaluator.rotate_rows_inplace(zz3[j], j, gal_keys);
       evaluator.relinearize_inplace(zz3[j], relin_keys16);
       evaluator.rotate_rows_inplace(zz4[j], j, gal_keys);
       evaluator.relinearize_inplace(zz4[j], relin_keys16);
     }

     for(int64_t u=1 ; u<row_size ; u++){
       evaluator.add_inplace(ct_HM1, zz3[u]);
       evaluator.add_inplace(ct_HM2, zz4[u]);
     }

     ofstream result_hm;
     result_hm.open(s2+"/HM1HM2_"+s1, ios::binary);//s1 now is the date!
     ct_HM1.save(result_hm);
     ct_HM2.save(result_hm);
     result_hm.close();

    cout<<"=====End====="<<endl;
    auto endWhole=chrono::high_resolution_clock::now();
    chrono::duration<double> diffWhole = endWhole-startWhole;
    cout << "Whole runtime is: " << diffWhole.count() << "s" << endl;
    show_memory_usage(getpid());

  return 0;
}
