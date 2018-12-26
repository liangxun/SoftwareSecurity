import os
import random
import subprocess

random.seed(1)

rootdir = "../../Data/SoftwareSecurity"
reverse_dir = "./data/reverse"

malware_apks = os.listdir(os.path.join(rootdir, 'malware_apks'))
normal_apks = os.listdir(os.path.join(rootdir, 'normal_apks'))
print(len(malware_apks), len(normal_apks))

cnt = 1
in_dir = rootdir+'/malware_apks'
out_dir = reverse_dir+'/malware'
malware_apks = malware_apks[:100]
for apk in malware_apks:
    print('apk{}:'.format(cnt), apk)
    inp = in_dir+'/{}'.format(apk)
    outp = out_dir+'/{}'.format(cnt)
    if os.path.exists(outp):
        print("already exits.")
    else:
        print("reverse from {} to {}".format(inp, outp))
        os.system('apktool d {} -o {}'.format(inp, outp))
    cnt += 1




