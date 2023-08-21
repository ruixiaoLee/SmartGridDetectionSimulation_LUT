//202112@Richelle
//୧(๑•̀⌄•́๑)૭✧
#include "sg_simulation.hpp"

using namespace std;
using namespace seal;

//only AM!

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

  Encryptor encryptor(context, public_key);
  Evaluator evaluator(context);

  BatchEncoder batch_encoder(context);
  IntegerEncoder encoder(context);
  size_t slot_count = batch_encoder.slot_count();
  size_t row_size = slot_count/2;
  cout << "Plaintext matrix row size: " << row_size << endl;
  cout << "Slot nums = " << slot_count << endl;

  int64_t row_count_AM=ceil((double)TABLE_SIZE_AM/(double)row_size);
  int64_t row_count_HM=ceil((double)TABLE_SIZE_HM/(double)row_size);
  int64_t sum_row_count_AM=ceil((double)TABLE_SIZE_AM_INV/(double)row_size);
  int64_t div_row_count_HM=ceil((double)TABLE_SIZE_DIV_HM/(double)row_size);

  cout<<"AM row "<<row_count_AM<<", HM row "<<row_count_HM<<endl;
  //read output table
  vector<Ciphertext> output_AM;
  vector<Ciphertext> output_HM;

  ifstream readtable_part1;
  readtable_part1.open("Table/AM_output_new1_"+to_string(METER_NUM));
  for(int w = 0; w < row_count_AM ; w++) {
    Ciphertext temp;
    temp.load(context, readtable_part1);
    output_AM.push_back(temp);
  }
  vector<Ciphertext> res_a;
  Ciphertext sum_result_a, sum_result_am_r;

    for(int64_t i=0 ; i<row_count_AM ; i++){
      Ciphertext tep;
      res_a.push_back(tep);
    }

    string s1(argv[1]);//Date
    string s2(argv[2]);//Result dir name
    string s3(argv[3]);//hour No.
////////////////////////////////////////////////////////////////////
    cout<<"=====Main====="<<endl;
    // for(int64_t iter=0 ; iter<24 ; iter++){ //24hours
    int64_t iter=stoi(s3); //hour
    //read index and PIR query from file
    cout << "===Reading query from DS===" << endl;
    ifstream PIRqueryFile(s2+"/pir_AM_new_"+to_string(iter));//Here changed!
    Ciphertext ct_query_AM0, ct_query_AM1;
    ct_query_AM0.load(context, PIRqueryFile);
    ct_query_AM1.load(context, PIRqueryFile);
    PIRqueryFile.close();
    cout<<"Reading query from DS > OK"<<endl;
    cout<<"LUT Processing"<<endl;

    // omp_set_num_threads(NF);
    // #pragma omp parallel for
    for (int64_t j=0 ; j<row_count_AM ; j++){
      Ciphertext temp_a = ct_query_AM1;
      evaluator.rotate_rows_inplace(temp_a, -j, gal_keys);
      evaluator.multiply_inplace(temp_a, ct_query_AM0);
      evaluator.relinearize_inplace(temp_a, relin_keys16);
      evaluator.multiply_inplace(temp_a, output_AM[j]);
      evaluator.relinearize_inplace(temp_a, relin_keys16);
      res_a[j]=temp_a;
    }
  // //result sum
    cout<<"===Sum result==="<<endl;
    sum_result_a = res_a[0];
    for(int k=1 ; k<row_count_AM ; k++){
      evaluator.add_inplace(sum_result_a, res_a[k]);
    }

    sum_result_am_r=sum_result_a;
    // totalSum
    for(int64_t i=0 ; i<log2(row_size) ; i++){
      Ciphertext ct = sum_result_am_r;
      evaluator.rotate_rows_inplace(ct, -pow(2,i), gal_keys);
      // evaluator.relinearize_inplace(ct, relin_keys16);
      evaluator.add_inplace(sum_result_am_r, ct);
    }//此处每个小时的结果已经totalSum过。

    Ciphertext AM_rec;// final AM and HM result(24 hours)
    // cout<<"We have "<<sum_result_am_r.size()<<" AM."<<endl;
    //读入前一个小时的AM_rec值，将这个小时的加到后面
    if(iter==0){
     AM_rec = sum_result_am_r;
     //save
     ofstream sumAMof;
     sumAMof.open(s2+"/sumAM_0", ios::binary);
     AM_rec.save(sumAMof);
    }
    else if(iter==23){
      ifstream sumAMif;
      sumAMif.open(s2+"/sumAM_"+to_string(iter-1), ios::binary);
      AM_rec.load(context, sumAMif);
      evaluator.add_inplace(AM_rec, sum_result_am_r);
      evaluator.relinearize_inplace(AM_rec, relin_keys16);

  //LUT sumAM => 1/sumAM
      vector<Ciphertext> AM_tab;
      cout<<"Read table for sum 1/AM."<<endl;
      ifstream read_AMTable;
      read_AMTable.open("Table/SUM_AM_input_new5_"+to_string(METER_NUM));
      for(int w = 0; w < sum_row_count_AM ; w++) {
        Ciphertext temps;
        temps.load(context, read_AMTable);
        AM_tab.push_back(temps);
      }

  //read table
      ofstream result_AM;
      result_AM.open(s2+"/inv_SUM_AM_"+s1, ios::binary);//s1 now is the date!
      for(int64_t j1=0 ; j1<sum_row_count_AM ; j1++){
        Ciphertext temp_AM_input = AM_rec;
        evaluator.sub_inplace(temp_AM_input, AM_tab[j1]);
        evaluator.relinearize_inplace(temp_AM_input, relin_keys16);
        temp_AM_input.save(result_AM);
      }
      result_AM.close();
    }
    else{
      ifstream sumAMif;
      sumAMif.open(s2+"/sumAM_"+to_string(iter-1), ios::binary);
      AM_rec.load(context, sumAMif);
      evaluator.add_inplace(AM_rec, sum_result_am_r);
      evaluator.relinearize_inplace(AM_rec, relin_keys16);
      ofstream sumAMof;
      sumAMof.open(s2+"/sumAM_"+to_string(iter), ios::binary);
      AM_rec.save(sumAMof);
    }

    cout<<"=====End====="<<endl;
    auto endWhole=chrono::high_resolution_clock::now();
    chrono::duration<double> diffWhole = endWhole-startWhole;
    cout << "Whole runtime is: " << diffWhole.count() << "s" << endl;
    show_memory_usage(getpid());

    return 0;
}
