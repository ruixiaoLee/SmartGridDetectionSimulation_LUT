#include "sg_simulation.hpp"
#include <numeric>
using namespace std;
using namespace seal;
typedef std::tuple<Ciphertext, Ciphertext> record;

unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
std::mt19937 generator(seed);

void output_plaintext(const vector<vector <int64_t>> &a){
  int64_t row=a.size();
  int64_t col=a[0].size();
  //cout<<"row:"<<row<<", col:"<<col<<endl;

  for(int i=0 ; i<row ; i++){
      for(int j=0 ; j<col ; j++){
            cout<<a[i][j]<<" ";
      }
      cout<<endl;
  }
}

int main(int argc, char *argv[]){
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
  size_t row_size = slot_count/2;
  cout << "Plaintext matrix row size: " << row_size << endl;
  cout << "Slot nums = " << slot_count << endl;

  Plaintext poly_dec_result1, poly_dec_result2;
  Ciphertext temp1, temp2;
  vector<int64_t> dec_result1, dec_result2;
  double tempRes1=0.0, temps=0.0;

  string s1(argv[1]);//Date
  string s2(argv[2]);//Result dir name
  string s3(argv[3]);//result save file
  vector<double> timeSlot_res;

  ifstream readFun1(s2+"/finalRes_"+s1, ios::binary);
  temp1.load(context, readFun1);
  readFun1.close();

  cout << "part1 Size after relinearization: " << temp1.size() << endl;
  cout << "Noise budget after relinearizing (dbc = "
      << relin_keys16.decomposition_bit_count() << endl;

  decryptor.decrypt(temp1, poly_dec_result1);
  batch_encoder.decode(poly_dec_result1, dec_result1);

  cout<<"dec:"<<dec_result1[0]<<endl;
  tempRes1 = dec_result1[0]*10000/pow(2,30);

  cout<<endl;

  cout<<"Final result:"<<tempRes1<<endl;
  ofstream ct_ratio; //
  ct_ratio.open(s3, ios::app);
  ct_ratio<<tempRes1<<endl;
  ct_ratio.close();

  cout<<"stop"<<endl;

  return 0;
}
