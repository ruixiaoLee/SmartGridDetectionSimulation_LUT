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

  Encryptor encryptor(context, public_key);
  Evaluator evaluator(context);

  BatchEncoder batch_encoder(context);
  IntegerEncoder encoder(context);
  size_t slot_count = batch_encoder.slot_count();
  size_t row_size = slot_count/2;
  cout << "Plaintext matrix row size: " << slot_count << endl;
  cout << "Slot nums = " << slot_count << endl;

  int64_t inv100_row=ceil((double)TABLE_SIZE_100_INV/(double)row_size);
  //////////////////////////////////////////////////////////////////////////////
  //read output table
  vector<Ciphertext> output_inv;

  ifstream readtable_part1;
  readtable_part1.open("Table/inv_100_output_new5_"+to_string(METER_NUM));
  for(int w = 0; w < inv100_row ; w++) {
    Ciphertext temp;
    temp.load(context, readtable_part1);
    output_inv.push_back(temp);
  }

  vector<Ciphertext> res_a;
  Ciphertext sum_result_a;
  //res_a: result of one time slot AM for each row
  //sum_result_a: result of one time slot AM (sum all row)
  //sum_result_am_r: result of 24 time slots AM (sum all time slots)
  //res_h1,2: result of one time slot HM for each row
  //sum_result_h1,2: result of one time slot AM (sum all row)
  //sum_result_hm_r1,2: result of 24 time slots AM (sum all time slots)

  for(int64_t i=0 ; i<inv100_row ; i++){
    Ciphertext tep;
    res_a.push_back(tep);
  }

  string s1(argv[1]);//Date
  string s2(argv[2]);//Result dir name
////////////////////////////////////////////////////////////////////
  cout<<"=====Main====="<<endl;

    //read index and PIR query from file
    cout << "===Reading query from DS===" << endl;
    ifstream PIRqueryFile(s2+"/pir_inv_"+s1);
    Ciphertext ct_query_inv0, ct_query_inv1;
    ct_query_inv0.load(context, PIRqueryFile);
    ct_query_inv1.load(context, PIRqueryFile);
    PIRqueryFile.close();
    cout<<"Reading query from DS > OK"<<endl;
    cout<<"LUT Processing"<<endl;
    auto startLUT=chrono::high_resolution_clock::now();

    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int64_t j=0 ; j<inv100_row ; j++){
      Ciphertext temp_a = ct_query_inv1;
      evaluator.rotate_rows_inplace(temp_a, -j, gal_keys);
      evaluator.multiply_inplace(temp_a, ct_query_inv0);
      evaluator.relinearize_inplace(temp_a, relin_keys16);
      evaluator.multiply_inplace(temp_a, output_inv[j]);
      evaluator.relinearize_inplace(temp_a, relin_keys16);
      res_a[j]=temp_a;
    }

    // //result sum
    cout<<"===Sum result==="<<endl;
    sum_result_a = res_a[0];
    for(int k=1 ; k<inv100_row ; k++){
      evaluator.add_inplace(sum_result_a, res_a[k]);
    }

    auto endLUT=chrono::high_resolution_clock::now();
    chrono::duration<double> diffLUT=endLUT-startLUT;
    cout<<"Runtimt of LUT: "<<diffLUT.count()<<"s"<<endl;
    auto startTotalSum=chrono::high_resolution_clock::now();

    Ciphertext fin_res=sum_result_a;
    for(int64_t i=0 ; i<log2(row_size) ; i++){
      Ciphertext ct1 = fin_res;
      evaluator.rotate_rows_inplace(ct1, -pow(2,i), gal_keys);
      evaluator.relinearize_inplace(ct1, relin_keys16);
      evaluator.add_inplace(fin_res, ct1);
    }//此处每个小时的结果已经totalSum过。


    auto endTotalSum=chrono::high_resolution_clock::now();
    chrono::duration<double> diffTotalSum=endTotalSum-startTotalSum;
    cout<<"Runtime for one time totalSum: "<<diffTotalSum.count()<<"s"<<endl;

    ifstream read_hmam(s2+"/Fin_AM1HM1_"+s1);
    Ciphertext am1hm1;
    am1hm1.load(context, read_hmam);
    read_hmam.close();

    evaluator.add_inplace(fin_res, am1hm1);

    cout<<"Save result"<<endl;

    ofstream save_fin;
    save_fin.open(s2+"/finalRes_"+s1,ios::binary);
    fin_res.save(save_fin);
    save_fin.close();
///
    //ofstream save_demo;
    //save_demo.open(s2+"/hm1am2hm2am1",ios::binary);
    //fin_res.save(save_demo);
    //save_demo.close();
///
    cout<<"=====End====="<<endl;
    auto endWhole=chrono::high_resolution_clock::now();
    chrono::duration<double> diffWhole = endWhole-startWhole;
    cout << "Whole runtime is: " << diffWhole.count() << "s" << endl;
    show_memory_usage(getpid());

  return 0;
}
