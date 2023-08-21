//make_inte_inv_100

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

    int64_t inv100_row=ceil((double)TABLE_SIZE_100_INV/(double)row_size);
    string s1(argv[1]);
    string s2(argv[2]);
//read AM1 AM2 HM1 HM2
    ifstream result_1;
    result_1.open(s2+"/AM1AM2_"+s1, ios::binary);
    ifstream result_2;
    result_2.open(s2+"/HM1HM2_"+s1, ios::binary);
    Ciphertext ct_AM1,ct_AM2,ct_HM1,ct_HM2;
    ct_AM1.load(context, result_1);
    ct_AM2.load(context, result_1);
    ct_HM1.load(context, result_2);
    ct_HM2.load(context, result_2);
    result_1.close();
    result_2.close();

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
    read_invTable.open("Table/inv_100_input_new4_"+to_string(METER_NUM));
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
