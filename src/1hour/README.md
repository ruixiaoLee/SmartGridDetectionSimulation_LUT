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
To use the codes, you need to add the dataset `DateWiseData` and `CMakeList.txt` same as `~/24hour` in here.
The code in this file could be run as follow.
```
step1_CS1 -> step2_TA1 -> step3_CS2_1 -> step4_TA2 -> step5_CS3_1 -> step5_CS3 -> step6_TA3 -> step7_CS4
                       -> step3_CS2_2              -> step5_CS3_2
```
Running the codes, you can add a script as `~/24hour`.
```
bin/step1_CS1 + 'path' + 'datetime' + .txt ptxt_res/'plaintext result file' Result
bin/step2_TA1 Result
bin/step3_CS2_1 + 'datetime' + Result (bin/step3_CS2_2 + 'datetime' + Result)
bin/step4_TA2 + 'datetime' + Result
bin/step5_CS3_1 + 'datetime' + Result (bin/step5_CS3_2 + 'datetime' + Result)
bin/step5_CS3 + 'datetime' + Result
bin/step6_TA3 + 'datetime' + Result
bin/step7_CS4 + 'datetime' + Result
bin/checkRes + 'datetime' + Result ctxt_res/'ciphertext result file'
```
