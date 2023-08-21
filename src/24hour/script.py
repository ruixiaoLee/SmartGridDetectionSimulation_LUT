import os
import subprocess
import datetime
import time
import shutil

begin = datetime.date(2014,1,1) # set the date of data here
end = datetime.date(2014,12,30)   # we did not use the data of 2/29
path = 'DateWiseData/NormalWinso/2014/' # set the row data file here

day = begin
delta = datetime.timedelta(days=1)
(status1, output1) = subprocess.getstatusoutput('make')
print(status1, output1)
(status2, output2) = subprocess.getstatusoutput('bin/makeEnctab_1')
print(status2, output2)

i = 0
start = time.process_time()
while day <= end:
    today = day.strftime("%Y-%m-%d")
    print(i,today)
    outRes = open("ctxt_res/test2014.txt", mode='a')
    outRes.write('%d,'%i)
    outRes.close()
    outResP = open("ptxt_res/test2014.txt", mode='a')
    outResP.write('%d,'%i)
    outResP.close()
    (status3, output3) = subprocess.getstatusoutput('bin/step1_CS1 '+path+today+'.txt ptxt_res/test2014.txt Result')
    print(status3, output3)
    (status4, output4) = subprocess.getstatusoutput('bin/step2_TA1 Result')
    print(status4, output4)
    (status5, output5) = subprocess.getstatusoutput('bin/step3_CS2 '+today+' Result')
    print(status5, output5)
    (status6, output6) = subprocess.getstatusoutput('bin/step4_TA2 '+today+' Result')
    print(status6, output6)
    (status7, output7) = subprocess.getstatusoutput('bin/step5_CS3 '+today+' Result')
    print(status7, output7)
    (status8, output8) = subprocess.getstatusoutput('bin/step6_TA3 '+today+' Result')
    print(status8, output8)
    (status9, output9) = subprocess.getstatusoutput('bin/step7_CS4 '+today+' Result')
    print(status9, output9)
    (status10, output10) = subprocess.getstatusoutput('bin/checkRes '+today+' Result ctxt_res/test2014.txt')
    print(status10, output10)
    shutil.rmtree('Result')
    os.mkdir('Result')
    day += delta
    i+=1
end = time.process_time()
print(end-start)
