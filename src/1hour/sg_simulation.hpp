#include <map>
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <unistd.h>
#include <string>
#include <tuple>
#include <vector>
#include <cstring>
#include <math.h>
#include <cstdio>
#include <chrono>
#include <random>
#include <thread>
#include <future>
#include <ctime>
#include <ratio>
#include <cstddef>
#include <iomanip>
#include <mutex>
#include <memory>
#include <limits>
#include <stdlib.h>
#include <stdio.h>
#include "seal/seal.h"
#define METER_NUM 150
#define TABLE_SIZE_AM 2850
#define TABLE_SIZE_HM 2653
#define TABLE_SIZE_AM_INV 3647
#define TABLE_SIZE_100_INV 3647
#define TABLE_SIZE_DIV_HM 7935
//1/ArithmeticMean
// #define TABLE_SIZE_SUM_HM 3625
//HarmonicMean
// #define TABLE_SIZE_OUT 13227625
#include "omp.h"
#define NF 16 //The number of threads
// METER_NUM=150,TABLE_SIZE_AM=22795,TABLE_SIZE_HM=663,TABLE_SIZE_OUT=15113085(2014)
// METER_NUM=188,TABLE_SIZE_AM=18784,TABLE_SIZE_HM=831,TABLE_SIZE_OUT=15609504(2015)
// METER_NUM=168,TABLE_SIZE_AM=20265,TABLE_SIZE_HM=743,TABLE_SIZE_OUT=15056895(2016)
#define PRECISION pow(2,5)
#define PRECISION2 pow(2,10)
