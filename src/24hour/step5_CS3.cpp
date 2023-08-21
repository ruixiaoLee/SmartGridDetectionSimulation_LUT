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
  //////////////////////////////////////////////////////////////////////////////
  //read output table
  vector<Ciphertext> output_AM1, output_AM2;

  ifstream readtable_part1;
  readtable_part1.open("Table/inv_SUM_AM_output1_"+to_string(METER_NUM));
  ifstream readtable_part2;
  readtable_part2.open("Table/inv_SUM_AM_output2_"+to_string(METER_NUM));
  for(int w = 0; w < sum_row_count_AM ; w++) {
    Ciphertext temp1, temp2;
    temp1.load(context, readtable_part1);
    temp2.load(context, readtable_part2);
    output_AM1.push_back(temp1);
    output_AM2.push_back(temp2);
  }

  vector<Ciphertext> res_a1, res_a2;
  Ciphertext AM_rec1, AM_rec2;
  for(int64_t i=0 ; i<sum_row_count_AM ; i++){
    Ciphertext tep;
    res_a1.push_back(tep);
    res_a2.push_back(tep);
  }

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
    ifstream PIRqueryFile(s2+"/pir_SUM_AM_DIV_HM_"+s1);
    Ciphertext ct_query_AM0, ct_query_AM1, ct_query_HM0, ct_query_HM1;
    ct_query_AM0.load(context, PIRqueryFile);
    ct_query_AM1.load(context, PIRqueryFile);
    ct_query_HM0.load(context, PIRqueryFile);
    ct_query_HM1.load(context, PIRqueryFile);
    PIRqueryFile.close();
    cout<<"Reading query from DS > OK"<<endl;
    cout<<"LUT Processing"<<endl;
    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int64_t j=0 ; j<sum_row_count_AM ; j++){
      Ciphertext temp_a1 = ct_query_AM1;
      Ciphertext temp_a2 = ct_query_AM1;
      evaluator.rotate_rows_inplace(temp_a1, -j, gal_keys);
      evaluator.rotate_rows_inplace(temp_a2, -j, gal_keys);
      evaluator.multiply_inplace(temp_a1, ct_query_AM0);
      evaluator.multiply_inplace(temp_a2, ct_query_AM0);
      evaluator.relinearize_inplace(temp_a1, relin_keys16);
      evaluator.relinearize_inplace(temp_a2, relin_keys16);
      evaluator.multiply_inplace(temp_a1, output_AM1[j]);
      evaluator.multiply_inplace(temp_a2, output_AM2[j]);
      evaluator.relinearize_inplace(temp_a1, relin_keys16);
      evaluator.relinearize_inplace(temp_a2, relin_keys16);
      res_a1[j]=temp_a1;
      res_a2[j]=temp_a2;
    }

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
    AM_rec1 = res_a1[0];
    AM_rec2 = res_a2[0];
    for(int k=1 ; k<sum_row_count_AM ; k++){
      evaluator.add_inplace(AM_rec1, res_a1[k]);
      evaluator.add_inplace(AM_rec2, res_a2[k]);
    }
    cout << "Size after relinearization: " << AM_rec1.size() << endl;

    HM_rec1 = res_h1[0];
    HM_rec2 = res_h2[0];
    for(int k=1 ; k<div_row_count_HM ; k++){
      evaluator.add_inplace(HM_rec1, res_h1[k]);
      evaluator.add_inplace(HM_rec2, res_h2[k]);
    }
    cout << "Size after relinearization: " << HM_rec1.size() << endl;

     Ciphertext ct_AM1 = AM_rec1; //AM_rec1: sum all row
     Ciphertext ct_AM2 = AM_rec2; //AM_rec2: sum all row
     Ciphertext ct_HM1 = HM_rec1; //HM_rec1: sum all row
     Ciphertext ct_HM2 = HM_rec2; //HM_rec2: sum all row

     for(int64_t i=0 ; i<log2(row_size) ; i++){
       Ciphertext ct1 = ct_AM1;
       Ciphertext ct2 = ct_AM2;
       Ciphertext ct3 = ct_HM1;
       Ciphertext ct4 = ct_HM2;
       evaluator.rotate_rows_inplace(ct1, -pow(2,i), gal_keys);
       evaluator.relinearize_inplace(ct1, relin_keys16);
       evaluator.add_inplace(ct_AM1, ct1);
       evaluator.rotate_rows_inplace(ct2, -pow(2,i), gal_keys);
       evaluator.relinearize_inplace(ct2, relin_keys16);
       evaluator.add_inplace(ct_AM2, ct2);
       evaluator.rotate_rows_inplace(ct3, -pow(2,i), gal_keys);
       evaluator.relinearize_inplace(ct3, relin_keys16);
       evaluator.add_inplace(ct_HM1, ct3);
       evaluator.rotate_rows_inplace(ct4, -pow(2,i), gal_keys);
       evaluator.relinearize_inplace(ct4, relin_keys16);
       evaluator.add_inplace(ct_HM2, ct4);
     }//此处每个小时的结果已经totalSum过。

    Ciphertext fin_AM1HM1, fin_AM1HM2, fin_AM2HM1, fin_AM1HM2AM2HM1;
    fin_AM1HM1 = ct_AM1;
    fin_AM1HM2 = ct_AM1;
    fin_AM2HM1 = ct_AM2;
    evaluator.multiply_inplace(fin_AM1HM1, ct_HM1);
    evaluator.multiply_inplace(fin_AM1HM2, ct_HM2);
    evaluator.multiply_inplace(fin_AM2HM1, ct_HM1);
    fin_AM1HM2AM2HM1 = fin_AM1HM2;
    evaluator.add_inplace(fin_AM1HM2AM2HM1, fin_AM2HM1);

    evaluator.relinearize_inplace(fin_AM1HM1, relin_keys16);
    evaluator.relinearize_inplace(fin_AM1HM2AM2HM1, relin_keys16);
///budget check
    cout << "Noise budget in fin_AM1HM1: "
       << decryptor.invariant_noise_budget(fin_AM1HM1) << " bits" << endl;
    cout << "Noise budget in fin_AM1HM2AM2HM1: "
      << decryptor.invariant_noise_budget(fin_AM1HM2AM2HM1) << " bits" << endl;

    Plaintext poly1,poly2;
    vector<int64_t> pt1,pt2;
    decryptor.decrypt(ct_AM1, poly1);
    batch_encoder.decode(poly1, pt1);
    decryptor.decrypt(ct_AM2, poly2);
    batch_encoder.decode(poly2, pt2);
    for(int64_t o=0;o<row_size;o++){
        cout<<"AM1:"<<pt1[o]<<", AM2:"<<pt2[o]<<endl;
    }
///
    ofstream result_am1hm1;
    result_am1hm1.open(s2+"/Fin_AM1HM1_"+s1, ios::binary);//s1 now is the date!
    fin_AM1HM1.save(result_am1hm1);
    result_am1hm1.close();

//LUT sumAM => 1/sumAM
    vector<Ciphertext> inv_tab;
    cout<<"Read table for sum 1/AM."<<endl;
    ifstream read_invTable;
    read_invTable.open("Table/inv_100_input_"+to_string(METER_NUM));
    for(int w = 0; w < inv100_row ; w++) {
      Ciphertext temps;
      temps.load(context, read_invTable);
      inv_tab.push_back(temps);
    }

//read table
    ofstream result_inv;
    result_inv.open(s2+"/inv_100_"+s1, ios::binary);//s1 now is the date!

    // omp_set_num_threads(NF);
    // #pragma omp parallel for
    for(int64_t j1=0 ; j1 < inv100_row ; j1++){
      Ciphertext inv_input = fin_AM1HM2AM2HM1;
      evaluator.sub_inplace(inv_input, inv_tab[j1]);
      evaluator.relinearize_inplace(inv_input, relin_keys16);
      inv_input.save(result_inv);
    }
    result_inv.close();

    cout<<"=====End====="<<endl;
    auto endWhole=chrono::high_resolution_clock::now();
    chrono::duration<double> diffWhole = endWhole-startWhole;
    cout << "Whole runtime is: " << diffWhole.count() << "s" << endl;
    show_memory_usage(getpid());

  return 0;
}
