//201911@Richelle
//୧(๑•̀⌄•́๑)૭✧
#include "sg_simulation.hpp"

//when the number of column >= row
using namespace seal;
using namespace std;

void show_memory_usage(pid_t pid){ //for Linux
  ostringstream path;
  path << "/proc/" << pid << "/status";
  ostringstream cmd;
  cmd << "grep -e 'VmHWM' -e 'VmSize' -e 'VmStk' -e 'VmData' -e 'VmExe' "<<path.str();
  system(cmd.str().c_str());
  return;
}

vector<int64_t> shift_work(const vector<int64_t> &query, const int64_t &index, const int64_t &num_slots){
  vector<int64_t> new_index;
  int64_t size = query.size();
  int64_t temp;

  for(int64_t i=0 ; i<num_slots ; i++){
    if((i+index) >= size) temp = query[i+index-size];
    else temp=query[i+index];
    new_index.push_back(temp);
  }

  return new_index;
}

  void out_vector(const vector<int64_t> &a){
    for(int j=0 ; j<a.size() ; j++){
      //cout<<a[j]<<" ";
      //if(a[j]==2) cout<<"\033[1;33mHere\033[0m";
      if(a[j]!=0) cout<<"\033[1;34m"<<a[j]<<"j:"<<j<<"\033[0m";
      //else cout<<a[j]<<" ";
    }
    cout<<endl;
  }

  void output_plaintext(const vector<vector <int64_t>> &a){
    int64_t row=a.size();
    int64_t col=a[0].size();
    cout<<"row:"<<row<<", col:"<<col<<endl;

    for(int i=0 ; i<row ; i++){
        for(int j=0 ; j<col ; j++){
              cout<<a[i][j]<<" ";
        }
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

  ifstream skFile("Key/SecretKey");
  SecretKey secret_key;
  secret_key.unsafe_load(skFile);
  skFile.close();

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
  Decryptor decryptor(context, secret_key);

  BatchEncoder batch_encoder(context);
  IntegerEncoder encoder(context);
  size_t slot_count = batch_encoder.slot_count();
  size_t row_size = slot_count/2 ;
  cout << "Plaintext matrix row size: " << row_size << endl;
  cout << "Slot nums = " << slot_count << endl;

  int64_t inv100_row=ceil((double)TABLE_SIZE_100_INV/(double)row_size);

  //////////////////////////////////////////////////////////////////////////////

  string s1(argv[1]);//Date
  string s2(argv[2]);//Result dir file
  vector<Ciphertext> ct_result;
  vector<vector<int64_t> > dec_result(inv100_row);
  vector<Plaintext> poly_dec_result;
  for(int i1=0 ; i1<inv100_row ; i1++){
    Plaintext ex;
    Ciphertext exx;
    poly_dec_result.push_back(ex);
    ct_result.push_back(exx);
  }

  cout<<"=====Main====="<<endl;

  ifstream result_1;
  result_1.open(s2+"/inv_100_"+s1, ios::binary);
  Ciphertext temp1;
  for(int w1 = 0; w1 < inv100_row ; w1++) {
    temp1.load(context, result_1);
    ct_result[w1]=temp1;
  }
  result_1.close();

  cout << "===Decrypting==="<< endl;
  omp_set_num_threads(NF);
  #pragma omp parallel for
  for (int z1=0 ; z1<inv100_row ; z1++){
    //cout<<"i: "<<z<<endl;
    Ciphertext result_temp1=ct_result[z1];
    decryptor.decrypt(result_temp1, poly_dec_result[z1]);
    batch_encoder.decode(poly_dec_result[z1], dec_result[z1]);
  }

  cout << "Decrypting > OK" << endl;

  cout << "===Making PIR-query===" << flush;
  cout<< "Search index of function 1"<<endl;
  int64_t index_row_x, index_col_x;
  int64_t flag1=0;
  for(int64_t i=0 ; i<inv100_row ; i++){
    for(int64_t j=0 ; j<row_size ; j++){//表格是从小到大的，结果是从正>负
      if(dec_result[i][j] >= 0 && dec_result[i][j+1] < 0 && flag1==0){
      //if(dec_result[i][j]==0){
        //  index_row_x=i;
        //  index_col_x=j;
        //  flag1=1;
      // }
        int64_t left1=dec_result[i][j];
        int64_t right1=abs(dec_result[i][j+1]);
        if(left1<=right1){
          flag1=1;
          index_row_x = i;
          index_col_x = j;
          break;
        }else{
          flag1=1;
          index_row_x = i;
          index_col_x = j+1;
          break;
        }
        cout<<"\033[1;31mxi:\033[0m"<<i<<"\033[1;31mxj:\033[0m"<<j<<endl;
      }
    }
  }
  cout<< "Got index of function inv"<<endl;
  if(flag1==0) cout<<"\033[1;31mERROR: NO FIND \033[0m"<<endl;

  cout<<"index_row_x:"<<index_row_x<<", index_col_x:"<<index_col_x<<endl;
  //out_vector(new_query0);
  cout << "OK" << endl;
  //new_index is new_query left_shift the value of index
  vector<int64_t> query_AM0, query_AM1;
  for(int64_t i=0 ; i<row_size ; i++){
    if(i==index_col_x) query_AM0.push_back(1);
    else query_AM0.push_back(0);
  }
  query_AM1 = shift_work(query_AM0, index_row_x, row_size);
  query_AM0.resize(slot_count);
  query_AM1.resize(slot_count);
  cout<<"Making PIR-query > OK"<<endl;

  cout << "===Encrypting===" << endl;
  Ciphertext ct_query_AM0, ct_query_AM1;
  Plaintext pt_query_AM0, pt_query_AM1;
  batch_encoder.encode(query_AM0, pt_query_AM0);
  encryptor.encrypt(pt_query_AM0, ct_query_AM0);
  batch_encoder.encode(query_AM1, pt_query_AM1);
  encryptor.encrypt(pt_query_AM1, ct_query_AM1);
  cout << "Encrypting > OK" << endl;

  //write in a file
  cout << "===Saving query===" << endl;
  ofstream queryFile;
  queryFile.open(s2+"/pir_inv_"+s1);
  ct_query_AM0.save(queryFile);
  ct_query_AM1.save(queryFile);
  queryFile.close();
      // cout << "Save query Hour."<<iter<<" > OK" << endl;
  cout<<"=====End====="<<endl;
  auto endWhole=chrono::high_resolution_clock::now();
  chrono::duration<double> diffWhole = endWhole-startWhole;
  cout << "Whole runtime is: " << diffWhole.count() << "s" << endl;
  show_memory_usage(getpid());

  return 0;
}
