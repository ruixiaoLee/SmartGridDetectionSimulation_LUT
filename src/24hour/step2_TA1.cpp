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

  int64_t row_count_fun1=ceil((double)TABLE_SIZE_AM/(double)row_size);
  int64_t row_count_fun2=ceil((double)TABLE_SIZE_HM/(double)row_size);

  //////////////////////////////////////////////////////////////////////////////

  string s1(argv[1]); //Result dir name
  vector<Ciphertext> ct_result1, ct_result2;
  vector<vector<int64_t> > dec_result1(row_count_fun1);
  vector<Plaintext> poly_dec_result1 ,poly_dec_result2;
  vector<vector<int64_t> > dec_result2(row_count_fun2);
  for(int i1=0 ; i1<row_count_fun1 ; i1++){
    Plaintext ex1;
    Ciphertext exx1;
    poly_dec_result1.push_back(ex1);
    ct_result1.push_back(exx1);
  }
  for(int i2=0 ; i2<row_count_fun2 ; i2++){
    Plaintext ex2;
    Ciphertext exx2;
    poly_dec_result2.push_back(ex2);
    ct_result2.push_back(exx2);
  }
  cout<<"=====Main====="<<endl;
  for(int64_t iter=0 ; iter<24 ; iter++){
      //cout<<"read the file"<<s1+"_"+to_string(iter)<<endl;
      ifstream result_1;
      result_1.open(s1+"/AM_"+to_string(iter), ios::binary);
      ifstream result_2;
      result_2.open(s1+"/HM_"+to_string(iter), ios::binary);
      Ciphertext temp1,temp2;
      for(int w1 = 0; w1 < row_count_fun1 ; w1++) {
        temp1.load(context, result_1);
        ct_result1[w1]=temp1;
      }
      for(int w2 = 0; w2 < row_count_fun2 ; w2++) {
        temp2.load(context, result_2);
        ct_result2[w2]=temp2;
      }
      result_1.close();
      result_2.close();

      cout << "===Decrypting==="<< endl;
      omp_set_num_threads(NF);
      #pragma omp parallel for
      for (int z1=0 ; z1<row_count_fun1 ; z1++){
        //cout<<"i: "<<z<<endl;
        Ciphertext result_temp1=ct_result1[z1];
        decryptor.decrypt(result_temp1, poly_dec_result1[z1]);
        batch_encoder.decode(poly_dec_result1[z1], dec_result1[z1]);
      }
      for (int z2=0 ; z2<row_count_fun2 ; z2++){
        //cout<<"i: "<<z<<endl;
        Ciphertext result_temp2=ct_result2[z2];
        decryptor.decrypt(result_temp2, poly_dec_result2[z2]);
        batch_encoder.decode(poly_dec_result2[z2], dec_result2[z2]);
      }
      cout << "Decrypting > OK" << endl;
      // output_plaintext(dec_result);
    ///////////////////////////////////////////////////////////////////
      //find the position of 0.
      cout << "===Making PIR-query===" << flush;
      cout<< "Search index of function 1"<<endl;
      int64_t index_row_x, index_col_x;
      int64_t flag1=0, flag2=0;
      for(int64_t i=0 ; i<row_count_fun1 ; i++){
        for(int64_t j=0 ; j<row_size ; j++){//表格是从小到大的，结果是从正>负
          if(dec_result1[i][j] >= 0 && dec_result1[i][j+1] < 0 && flag1==0){
            int64_t left1=dec_result1[i][j];
            int64_t right1=abs(dec_result1[i][j+1]);
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
            // cout<<"\033[1;31mxi:\033[0m"<<i<<"\033[1;31mxj:\033[0m"<<j<<endl;
          }
        }
      }
      cout<< "Got index of function 1"<<endl;
      if(flag1==0) cout<<"\033[1;31mERROR: NO FIND 1\033[0m"<<endl;
      cout<< "Search index of function 2"<<endl;
      int64_t index_row_y, index_col_y;
      for(int64_t i=0 ; i<row_count_fun2 ; i++){
        for(int64_t j=0 ; j<row_size ; j++){//结果是从负>正
          if(dec_result2[i][j]==0){
            index_row_y=i;
            index_col_y=j;
            break;
            flag2=1;
          }
          if(dec_result2[i][j] <= 0 && dec_result2[i][j+1] > 0 && flag2==0){
            int64_t left2=abs(dec_result2[i][j]);
            int64_t right2=dec_result2[i][j+1];
            if(left2<=right2){
              flag2=1;
              index_row_y = i;
              index_col_y = j;
              break;
            }else{
              flag2=1;
              index_row_y = i;
              index_col_y = j+1;
              break;
            }
          }
        }
      }
      cout<< "Got index of function 2"<<endl;
      if(flag2==0) cout<<"\033[1;31mERROR: NO FIND 2\033[0m"<<endl;
      cout<<"Hour."<<iter<<endl;
      cout<<"index_row_AM:"<<index_row_x<<", index_col_AM:"<<index_col_x<<", index_row_HM:"<<index_row_y<<", index_col_HM:"<<index_col_y<<endl;
      //out_vector(new_query0);
      cout << "OK" << endl;

      //此时我们得到两个index对，每一个都是对应的完全相同的index的output
      //现在头两个函数HM和AM各自拥有一个输出表

      //new_index is new_query left_shift the value of index
      vector<int64_t> query_AM0, query_AM1, query_HM0, query_HM1;
      for(int64_t i=0 ; i<row_size ; i++){
        if(i==index_col_x) query_AM0.push_back(1);
        else query_AM0.push_back(0);
      }
      query_AM1 = shift_work(query_AM0, index_row_x, row_size);
      query_AM0.resize(slot_count);
      query_AM1.resize(slot_count);

      for(int64_t i=0 ; i<row_size ; i++){
        if(i==index_col_y) query_HM0.push_back(1);
        else query_HM0.push_back(0);
      }
      query_HM1 = shift_work(query_HM0, index_row_y, row_size);
      query_HM0.resize(slot_count);
      query_HM1.resize(slot_count);
      cout<<"Making PIR-query > OK"<<endl;

      //encrypt new query
      cout << "===Encrypting===" << endl;
      Ciphertext ct_query_AM0, ct_query_AM1, ct_query_HM0, ct_query_HM1;
      Plaintext pt_query_AM0, pt_query_AM1, pt_query_HM0, pt_query_HM1;
      batch_encoder.encode(query_AM0, pt_query_AM0);
      encryptor.encrypt(pt_query_AM0, ct_query_AM0);
      batch_encoder.encode(query_AM1, pt_query_AM1);
      encryptor.encrypt(pt_query_AM1, ct_query_AM1);
      batch_encoder.encode(query_HM0, pt_query_HM0);
      encryptor.encrypt(pt_query_HM0, ct_query_HM0);
      batch_encoder.encode(query_HM1, pt_query_HM1);
      encryptor.encrypt(pt_query_HM1, ct_query_HM1);
      cout << "Encrypting > OK" << endl;

      //write in a file
      cout << "===Saving query===" << endl;
      ofstream queryFile;
      queryFile.open(s1+"/pir_AMHM_"+to_string(iter));
      ct_query_AM0.save(queryFile);
      ct_query_AM1.save(queryFile);
      ct_query_HM0.save(queryFile);
      ct_query_HM1.save(queryFile);
      queryFile.close();
      cout << "Save query Hour."<<iter<<" > OK" << endl;
  }
  cout<<"=====End====="<<endl;
  auto endWhole=chrono::high_resolution_clock::now();
  chrono::duration<double> diffWhole = endWhole-startWhole;
  cout << "Whole runtime is: " << diffWhole.count() << "s" << endl;
  show_memory_usage(getpid());

  return 0;
}
