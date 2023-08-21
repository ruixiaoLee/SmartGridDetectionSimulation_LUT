//202110
#include "sg_simulation.hpp"

using namespace std;
using namespace seal;

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

//make a map from files
map<string, vector<double> > read_data(const string &filename){
  //read power consumption as map
  //map<string, vector<float> > 包括一个string-时间，和一个vector-耗电量
  ifstream readData(filename);
  map<string, vector<double> > hour_data;
  string usage_str;
  string lineStr;
  string timeSt;
  vector<double> usage_hour;


  bool flag=true;
  while(getline(readData, lineStr)){ //each row as a new stringstream
    stringstream ss(lineStr);
    while(getline(ss, usage_str, ',')){ //divide as two part: a string and a new stringstream
      if(flag==true){
        timeSt=usage_str;
        flag=false;
        //cout<<"This is "<<timeSt<<endl;
      }
      else{
        double temp = stod(usage_str);
        usage_hour.push_back(temp);
        // cout<<"the usage data is:"<<temp<<endl;
      }
    }
    // Here if you don't need the first row which is the meters' number
    if(timeSt!="TimeSlot"){
      hour_data.insert(pair<string,vector<double> >(timeSt,usage_hour));
      //cout<<"Here we insert a line "<<timeSt<<" including "<<usage_hour.size()<<" data"<<endl;
    }
    // Here if you need the first row which is the meters' number
    /*
    hour_data.insert(pair<string,vector<float> >(timeSt,usage_hour));
    //cout<<"Here we insert a line "<<timeSt<<" including "<<usage_hour.size()<<" data"<<endl;
    usage_hour.clear();
    */
    usage_hour.clear();
    flag=true;
  }
  return hour_data;
}

vector<Ciphertext> shift_work(vector<Ciphertext> result, int64_t random_value){
  vector<Ciphertext> new_result;
  int64_t size = result.size();
  Ciphertext temp;

  for(int64_t i=0 ; i<size ; i++){
    if((i+random_value) >= size) temp = result[i+random_value-size];
    else temp = result[i+random_value];
    new_result.push_back(temp);
  }
  return new_result;
}

//Harmonic mean for a hour
double HarmonicMean(vector<double> x){
  double sum_hm_double=0.0, temp;
  // int64_t sum_hm_int=0, temp2, N;//四舍五入取整
  double result;
  // double precision = pow(2,5);
  int64_t N = x.size();
  for(int64_t i=0; i<x.size(); ++i){
    temp = 1 / log(x[i]+2);//scale 100 times
    sum_hm_double += temp;
  }
  return result = N / sum_hm_double;
}

//Arithmetic mean for a hour
double ArithmeticMean(vector<double> x){
  double sum_am_double=0.0,temp;
  // int64_t sum_am_int=0, temp2, N;
  double result;
  // double precision = pow(2,5);
  int64_t N = x.size();
  for(int64_t i=0; i<x.size(); ++i){
    temp = log(x[i]+2);//scale x times
    sum_am_double += temp;
  }
  return result = sum_am_double / N;
}

/* HERE is the main function!!! */
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
  int64_t row_count_AM=ceil((double)TABLE_SIZE_AM/(double)row_size);
  int64_t row_count_HM=ceil((double)TABLE_SIZE_HM/(double)row_size);

  //read table
  vector<Ciphertext> AM_tab;
  vector<Ciphertext> HM_tab;

  ifstream read_AMTable;
  read_AMTable.open("Table/AM_input_"+to_string(METER_NUM));
  for(int w = 0; w < row_count_AM ; w++) {
    Ciphertext temp1;
    temp1.load(context, read_AMTable);
    AM_tab.push_back(temp1);
  }
  ifstream read_HMTable;
  read_HMTable.open("Table/HM_input_"+to_string(METER_NUM));
  for(int w = 0; w < row_count_HM ; w++) {
    Ciphertext temp2;
    temp2.load(context, read_HMTable);
    HM_tab.push_back(temp2);
  }

  //read data
  string s1(argv[1]); //input the file name of usage
  string s2(argv[2]); //Plaintext result file name
  string s3(argv[3]); //Result dir name
  map<string, vector<double> > mapTimeData = read_data(s1);
  cout<<"Number of time slot is "<<mapTimeData.size()<<endl;

  //建立一个vector里面有24个元素，是24个小时每个小时的耗电量和
  // Sum the usage of per day
  int64_t timeslot;
  vector<Ciphertext> AM_sum_res, HM_sum_res;
  for(timeslot=0; timeslot<24 ; timeslot++){
    Ciphertext tts;
    AM_sum_res.push_back(tts);
    HM_sum_res.push_back(tts);
  }

  timeslot=0;
  double Sum_AM_time=0.0, Sum_HM_time=0.0;
  double AM_time, HM_time;
  cout<<"Number of time slot is "<<mapTimeData.size()<<endl;
  for(auto iter = mapTimeData.begin(); iter != mapTimeData.end(); ++iter){
    cout<<iter->first<<endl;
    cout<<"Number of data is "<<(iter->second).size()<<endl;

    Ciphertext log_sum, log_rec_sum;
    vector<double> x=iter->second;
    int64_t checksumlog=0, checksumreclog=0;
    double max_num=0;

    //24个小时
    cout<<"\033[31m===Sum Usage Processing===\033[0m"<<endl;
    for(auto iter2=x.begin(); iter2!=x.end(); ++iter2){
      // cout<<"\033[33m"<<*iter2<<"  \033[0m";
      int64_t temp = PRECISION * log(*iter2+2);//
      double tep = PRECISION * log(*iter2+2);
      int64_t temp_rec = PRECISION2 * 1 / log(*iter2+2);//扩大PRECISION倍
      double tep_rec = PRECISION2 * 1  / log(*iter2+2);

      //四舍五入取值log and 1/log
      if(abs(tep-temp)>=0.5){
        temp += 1;
      }
      if(abs(tep_rec-temp_rec)>=0.5){
        temp_rec += 1;
      }
      // 明文，确认数值用
      // cout<<"log:"<<temp<<", 1/log:"<<temp_rec<<endl;
      checksumlog+=temp;
      checksumreclog+=temp_rec;
      if(*iter2>=max_num) max_num = *iter2;
      // 每一个usage需要加密后，相加，再表探索。此处为加密填充一整个vector后加密成密文
      // 创建一个vector长度与行的大小一致，每一个元素都是耗电量的log值

      vector<int64_t> vec_log;
      for(int i=0 ; i<row_size ; i++){
        vec_log.push_back(temp);
      }
      vec_log.resize(slot_count);
      // 创建一个vector长度与行的大小一致，每一个元素都是耗电量的1/log值
      vector<int64_t> vec_rec_log;
      for(int i=0 ; i<row_size ; i++){
        vec_rec_log.push_back(temp_rec);
      }
      vec_rec_log.resize(slot_count);
      //encrypt the usage and add to log_sum
      Plaintext poly_log;
      batch_encoder.encode(vec_log, poly_log);
      Ciphertext log_enc;
      encryptor.encrypt(poly_log, log_enc);
      if(iter2 == x.begin())
        log_sum = log_enc;
      else
       evaluator.add_inplace(log_sum, log_enc);
      //evaluator.relinearize_inplace(log_sum, relin_keys16);

      //encrypt the 1/usage and add to rec_log_sum
      Plaintext poly_rec_log;
      batch_encoder.encode(vec_rec_log, poly_rec_log);
      Ciphertext rec_log_enc;
      encryptor.encrypt(poly_rec_log, rec_log_enc);
      if(iter2 == x.begin())
        log_rec_sum = rec_log_enc;
      else
       evaluator.add_inplace(log_rec_sum, rec_log_enc);
      evaluator.relinearize_inplace(log_rec_sum, relin_keys16);
     }

    AM_sum_res[timeslot]=log_sum;
    HM_sum_res[timeslot]=log_rec_sum;

    cout<<"CHECK TEST (INT)"<<endl;
    std::cout << "Sum log() is:" <<checksumlog<<", Sum 1/log() is:"<<checksumreclog<< '\n';
    cout<<"Max usage is: "<<max_num<<endl;
    AM_time = ArithmeticMean(x);
    HM_time = HarmonicMean(x);
    cout<<"Plaintext result >> AM:"<<AM_time<<", HM:"<<HM_time<<endl;
    checksumlog=0, checksumreclog=0;
    max_num=0;
    timeslot++;
    Sum_AM_time += AM_time;
    Sum_HM_time += HM_time;
    AM_time = 0.0;
    HM_time = 0.0;
  }
  double ratio=Sum_HM_time/Sum_AM_time;
  ////////////此处可以把这一天的结果存在文件中
  cout<<"Plaintext sum_AM:"<<Sum_AM_time<<", sum_HM:"<<Sum_HM_time<<", ratio result:"<<ratio<<endl;
  ofstream pt_ratio; // date_ArithMean_hour
  pt_ratio.open(s2, ios::app);
  pt_ratio<<ratio<<endl;
  pt_ratio.close();

   cout<<"\033[31m===Sum Usage Processing End===\033[0m"<<endl;
   auto endSum=chrono::high_resolution_clock::now();

   vector<Ciphertext> result_ct_AM, result_ct_HM;
   for(int64_t i=0 ; i<row_count_AM ; i++){
     Ciphertext temp_result;
     result_ct_AM.push_back(temp_result);
   }
   for(int64_t j=0 ; j<row_count_HM ; j++){
     Ciphertext temp_result;
     result_ct_HM.push_back(temp_result);
   }

  //table search
  cout<<"\033[32m===Table Search Processing===\033[0m"<<endl;

  // omp_set_num_threads(NF);
  // #pragma omp parallel for
  for(int64_t i=0 ; i<24 ; i++){
    //每个小时都有一个结果，这个结果中有和table的行数一样数量的密文的结果
    ofstream result_AM; // date_ArithMean_hour
    result_AM.open(s3+"/AM_"+to_string(i), ios::binary);
    ofstream result_HM;
    result_HM.open(s3+"/HM_"+to_string(i), ios::binary);
    cout<<"TIME SLOT: "<<i<<endl;
    // search sum of log and save
    omp_set_num_threads(NF);
    #pragma omp parallel for
    for(int64_t j1=0 ; j1<row_count_AM ; j1++){
      Ciphertext temp_AM_input=AM_sum_res[i];
      evaluator.sub_inplace(temp_AM_input, AM_tab[j1]);
      evaluator.relinearize_inplace(temp_AM_input, relin_keys16);
      result_ct_AM[j1]=temp_AM_input;
    }//endfor
    //shift results
    // result_ct_AM=shift_work(result_ct_AM, random_value_AM);
    for(int64_t j1=0 ; j1<row_count_AM ; j1++){
      result_ct_AM[j1].save(result_AM);
    }
    result_AM.close();

    // search sum of 1/log and save
    omp_set_num_threads(NF);
    #pragma omp parallel for
    for(int64_t j2=0 ; j2<row_count_HM ; j2++){
      Ciphertext temp_HM_input=HM_sum_res[i];
      evaluator.sub_inplace(temp_HM_input, HM_tab[j2]);
      result_ct_HM[j2]=temp_HM_input;
    }//endfor
    //shift results
    // result_ct_HM=shift_work(result_ct_HM, random_value_HM);
    for(int64_t j2=0 ; j2<row_count_HM ; j2++){
      result_ct_HM[j2].save(result_HM);
    }
    result_HM.close();
  }//endfor
  cout<<"\033[32m===Table Search Processing End===\033[0m"<<endl;

  auto endWhole=chrono::high_resolution_clock::now();
  chrono::duration<double> diff1 = endSum-startWhole;
  chrono::duration<double> diff2 = endWhole-endSum;
  cout << "Runtime sum is: " << diff1.count() << "s" << endl;
  cout << "Runtime LUT is: " << diff2.count() << "s" << endl;
  show_memory_usage(getpid());

  return 0;
}
