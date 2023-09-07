# Smart Grid Detection Simulation

# Contents
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Building on linux](#building-on-linux)
- [Running on linux](#running-on-linux)
- [How to use](#how-to-use)

# Introduction
Only tested on 64-bit platform.<br>
This is a demo to compute the harmonic mean arithmetic mean (HM-AM) ratio with FHE-based LUT for the privacy-preserving anomaly detection system.
You can check the details from the paper [Look-Up Table based FHE System for Privacy Preserving Anomaly Detection in Smart Grids](https://ieeexplore.ieee.org/document/9821108).<br>

# Prerequisites
- [Microsoft SEAL version 3.2.0](https://github.com/microsoft/SEAL)
- [CMake](https://cmake.org/)
- [OpenMP](https://www.openmp.org/)

# Building on linux
Microsoft SEAL version 3.2.0, CMake and OpenMP is needed.<br>
For a simply test, under the `~/24hour` directory, run the commands below.
```
cmake .
make
```

# Running on linux
For a simply test, under the `~/24hour` directory, run the commands below.
```
python3 script.py
```

# How to use
The dataset is `DateWiseData`, including `Attack` and `NormalWinso` data. <br>
The number of smart meters: 2015 - 150, 2016 - 188, 2017 - 168. <br>

Currently, the script compute the data from 2014-01-01 to 2014-12-30. To maintain data consistency, we do not use the data on 02-29 and 12-31. When you want to simulate the data in 2016, remember to remove the data on 2016-02-29.<br>

You can set the data you want to compute by editing the script and sg_simulation.hpp to set the corresponding number of meters.
After you edit the file, please compile the codes again.<br>

1. set the number of meters in `sg_simulation.hpp`.
2. run `make` and `bin/makeEnctab_1`(or 2,3) to get the table size of `TABLE_SIZE_AM`, `TABLE_SIZE_HM` and `TABLE_SIZE_OUT`.
3. set the number of table size in `sg_simulation.hpp`.
4. run `make` one more time.
5. run `script.py`, the results are saved in ctxt_res (decrypted result computed over ciphertext) and ptxt_res (result computed over plaintext).

### Code construciton
```
src  -- 24hour -- DateWiseData
               |_ ctxt_res # the ratio result computed by ciphertext(LUT)
               |_ ptxt_res # the ratio result computed by plaintext
               |_ Key
               |_ Table
               |_ Result
               |_ script.py
               |_ CMakeList.txt
               |_ # source code
                 |_ sg_simulation.hpp
                 |_ makeEnctab_1 # make LUTs for expriment1
                 |_ makeEnctab_2 # make LUTs for expriment2
                 |_ makeEnctab_3 # make LUTs for expriment3
                 |_ keyGen.cpp
                 |_ step1_CS1.cpp
                 |_ step2_TA1.cpp
                 |_ step3_CS2.cpp
                 |_ step4_TA2.cpp
                 |_ step5_CS3.cpp
                 |_ step6_TA3.cpp
                 |_ step7_CS4.cpp
                 |_ checkRes.cpp
     |_ 1 hour # the source codes to compute the ratio hour-by-hour
```
