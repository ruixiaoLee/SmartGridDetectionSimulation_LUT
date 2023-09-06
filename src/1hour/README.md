# Source code for one day simulation
The codes in this directory is for the one day simulation.

## Code construction
```
1hour ----- sg_simulation.hpp
         |_ keyGen.cpp
         |_ step1_CS1.cpp
         |_ step2_TA1.cpp
         |_ step3_CS2_1.cpp # run with step3_CS2.2.cpp at the same time
         |_ step3_CS2_2.cpp # run with step3_CS2.1.cpp at the same time
         |_ step4_TA2.cpp
         |_ step5_CS3_1.cpp # run with step5_CS3.2.cpp at the same time
         |_ step5_CS3_2.cpp # run with step5_CS3.1.cpp at the same time
         |_ step5_CS3.cpp
         |_ step6_TA3.cpp
         |_ step7_CS4.cpp
         |_ checkRes.cpp
```
# How to use
To use the codes, you need to add the dataset `DateWiseData` and `CMakeList.txt`in here.
The code in this file could be run as follow.
```
step1_CS1 -> step2_TA1 -> step3_CS2_1 -> step4_TA2 -> step5_CS3_1 -> step5_CS3 -> step6_TA3 -> step7_CS4
                       -> step3_CS2_2              -> step5_CS3_2
```
Currently, the script compute the data from 2014-01-01 to 2014-12-30. To maintain data consistency, we do not use the data on 02-29 and 12-31. When you want to simulate the data in 2016, remember to remove the data on 2016-02-29.<br>

You can set the data you want to compute by editing the script and sg_simulation.hpp to set the corresponding number of meters.
After you edit the file, please compile the codes again.<br>

1. set the number of meters in `sg_simulation.hpp`.
2. run `make` and `bin/makeEnctab_1`(or 2,3) to get the table size of `TABLE_SIZE_AM`, `TABLE_SIZE_HM` and `TABLE_SIZE_OUT`.
3. set the number of table size in `sg_simulation.hpp`.
4. run `make` one more time.
5. run `script.py`, the results are saved in ctxt_res (decrypted result computed over ciphertext) and ptxt_res (result computed over plaintext).
