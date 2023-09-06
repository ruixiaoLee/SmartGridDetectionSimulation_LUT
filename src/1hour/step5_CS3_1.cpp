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

    string s1(argv[1]);
    string s2(argv[2]);
////////////////////////////////////////////////////////////////////
    cout<<"=====Main====="<<endl;
    //read index and PIR query from file
    cout << "===Reading query from DS===" << endl;
    ifstream PIRqueryFile(s2+"/pir_SUM_AM_"+s1);
    Ciphertext ct_query_AM0, ct_query_AM1;
    ct_query_AM0.load(context, PIRqueryFile);
    ct_query_AM1.load(context, PIRqueryFile);
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

    // //result sum
    cout<<"===Sum result==="<<endl;
    AM_rec1 = res_a1[0];
    AM_rec2 = res_a2[0];
    for(int k=1 ; k<sum_row_count_AM ; k++){
      evaluator.add_inplace(AM_rec1, res_a1[k]);
      evaluator.add_inplace(AM_rec2, res_a2[k]);
    }
    cout << "Size after relinearization: " << AM_rec1.size() << endl;

     vector<Ciphertext> zz1, zz2;
     for(int64_t ss=0 ; ss<row_size; ss++){
       zz1.push_back(AM_rec1);
       zz2.push_back(AM_rec2);
     }
     Ciphertext ct_AM1 = AM_rec1; //AM_rec1: sum all row
     Ciphertext ct_AM2 = AM_rec2; //AM_rec2: sum all row

     omp_set_num_threads(NF);
     #pragma omp parallel for
     for(int64_t j=1 ; j<row_size ; j++){
       evaluator.rotate_rows_inplace(zz1[j], j, gal_keys);
       evaluator.relinearize_inplace(zz1[j], relin_keys16);
       evaluator.rotate_rows_inplace(zz2[j], j, gal_keys);
       evaluator.relinearize_inplace(zz2[j], relin_keys16);
     }

     for(int64_t u=1 ; u<row_size ; u++){
       evaluator.add_inplace(ct_AM1, zz1[u]);
       evaluator.add_inplace(ct_AM2, zz2[u]);
     }

     ofstream result_am;
     result_am.open(s2+"/AM1AM2_"+s1, ios::binary);//s1 now is the date!
     ct_AM1.save(result_am);
     ct_AM2.save(result_am);
     result_am.close();

    cout<<"=====End====="<<endl;
    auto endWhole=chrono::high_resolution_clock::now();
    chrono::duration<double> diffWhole = endWhole-startWhole;
    cout << "Whole runtime is: " << diffWhole.count() << "s" << endl;
    show_memory_usage(getpid());

    return 0;
}
