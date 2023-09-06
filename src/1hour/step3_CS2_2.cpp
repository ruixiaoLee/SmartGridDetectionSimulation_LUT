//202112@Richelle
//୧(๑•̀⌄•́๑)૭✧
#include "sg_simulation.hpp"

using namespace std;
using namespace seal;

//only HM!

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

  int64_t row_count_HM=ceil((double)TABLE_SIZE_HM/(double)row_size);
  int64_t div_row_count_HM=ceil((double)TABLE_SIZE_DIV_HM/(double)row_size);
  cout<<"HM row "<<row_count_HM<<endl;
  //////////////////////////////////////////////////////////////////////////////
  vector<Ciphertext> output_HM;

  ifstream readtable_hm;
  readtable_hm.open("Table/HM_output_"+to_string(METER_NUM));
  for(int w = 0; w < row_count_HM ; w++) {
    Ciphertext temp;
    temp.load(context, readtable_hm);
    output_HM.push_back(temp);
  }

  vector<Ciphertext> res_h;
  Ciphertext sum_result_h, sum_result_hm_r;
  //res_a: result of one time slot AM for each row
  //sum_result_a: result of one time slot AM (sum all row)
  //sum_result_am_r: result of 24 time slots AM (sum all time slots)
  //res_h1,2: result of one time slot HM for each row
  //sum_result_h1,2: result of one time slot AM (sum all row)
  //sum_result_hm_r1,2: result of 24 time slots AM (sum all time slots)

    for(int64_t i=0 ; i<row_count_HM ; i++){
      Ciphertext tep;
      res_h.push_back(tep);
    }

    string s1(argv[1]);//Date
    string s2(argv[2]);//Result dir name
    string s3(argv[3]);//hour No.
////////////////////////////////////////////////////////////////////
    cout<<"=====Main====="<<endl;
    // for(int64_t iter=0 ; iter<24 ; iter++){ //24hours
    int64_t iter=stoi(s3); //hour
    // read index and PIR query from file
    cout << "===Reading query from DS===" << endl;
    ifstream PIRqueryFile(s2+"/pir_HM_"+to_string(iter)); //Here
    Ciphertext ct_query_HM0, ct_query_HM1;

    ct_query_HM0.load(context, PIRqueryFile);
    ct_query_HM1.load(context, PIRqueryFile);
    PIRqueryFile.close();
    cout<<"Reading query from DS > OK"<<endl;
    cout<<"LUT Processing"<<endl;

    // omp_set_num_threads(NF);
    // #pragma omp parallel for
    for (int64_t k=0 ; k<row_count_HM ; k++){
      Ciphertext temp_h = ct_query_HM1;
      evaluator.rotate_rows_inplace(temp_h, -k, gal_keys);
      evaluator.multiply_inplace(temp_h, ct_query_HM0);
      evaluator.relinearize_inplace(temp_h, relin_keys16);
      evaluator.multiply_inplace(temp_h, output_HM[k]);
      evaluator.relinearize_inplace(temp_h, relin_keys16);
      res_h[k]=temp_h;
    }
    // //result sum
    cout<<"===Sum result==="<<endl;

    sum_result_h = res_h[0];
    for(int i=1 ; i<row_count_HM ; i++){
      evaluator.add_inplace(sum_result_h, res_h[i]);
    }

    sum_result_hm_r=sum_result_h;
    // totalSum
    for(int64_t i=0 ; i<log2(row_size) ; i++){
      Ciphertext ct = sum_result_hm_r;
      evaluator.rotate_rows_inplace(ct, -pow(2,i), gal_keys);
      // evaluator.relinearize_inplace(ct, relin_keys16);
      evaluator.add_inplace(sum_result_hm_r, ct);
    }//此处每个小时的结果已经totalSum过。

    Ciphertext HM_rec;// final AM and HM result(24 hours)
    if(iter==0){
     HM_rec = sum_result_hm_r;
     //save
     ofstream sumHMof;
     sumHMof.open(s2+"/sumHM_0", ios::binary);
     HM_rec.save(sumHMof);
    }
    else if(iter==23){
      ifstream sumHMif;
      sumHMif.open(s2+"/sumHM_"+to_string(iter-1), ios::binary);
      HM_rec.load(context, sumHMif);
      evaluator.add_inplace(HM_rec, sum_result_hm_r);
      evaluator.relinearize_inplace(HM_rec, relin_keys16);
//LUT sumHM => divide to sumHM 1, and sumHM 2. sumHM = sumHM1 * 100 + sumHM2

      vector<Ciphertext> HM_tab;
      cout<<"Read table for sum HM."<<endl;
      ifstream read_HMTable;
      read_HMTable.open("Table/div_HM_input_"+to_string(METER_NUM));
      for(int w = 0; w < div_row_count_HM ; w++) {
        Ciphertext temps;
        temps.load(context, read_HMTable);
        HM_tab.push_back(temps);
      }
  //read table
      ofstream result_HM;
      result_HM.open(s2+"/div_HM_"+s1, ios::binary);//s1 now is the date
      for(int64_t j1=0 ; j1<div_row_count_HM ; j1++){
        Ciphertext temp_HM_input = HM_rec;
        evaluator.sub_inplace(temp_HM_input, HM_tab[j1]);
        evaluator.relinearize_inplace(temp_HM_input, relin_keys16);
        temp_HM_input.save(result_HM);
      }
      result_HM.close();
    }
    else{
      ifstream sumHMif;
      sumHMif.open(s2+"/sumHM_"+to_string(iter-1), ios::binary);
      HM_rec.load(context, sumHMif);
      evaluator.add_inplace(HM_rec, sum_result_hm_r);
      evaluator.relinearize_inplace(HM_rec, relin_keys16);
      ofstream sumHMof;
      sumHMof.open(s2+"/sumHM_"+to_string(iter), ios::binary);
      HM_rec.save(sumHMof);
    }

    cout<<"=====End====="<<endl;
    auto endWhole=chrono::high_resolution_clock::now();
    chrono::duration<double> diffWhole = endWhole-startWhole;
    cout << "Whole runtime is: " << diffWhole.count() << "s" << endl;
    show_memory_usage(getpid());

    return 0;
}
