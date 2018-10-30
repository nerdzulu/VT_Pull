### Importing Modules
import virustotal

###Assigning API Key   
vt = virustotal.VirusTotal("")  ###### Enter API Key Here
#vta = raw_input("VT Api Key:")
#vt = virustotal.VirusTotal(vta)

md5_list1 = raw_input("MD5 list file:")
print(md5_list1)
sha256_list = []
export = raw_input("Export filename:")
md5_list1 = md5_list1.rstrip("\r")
print(md5_list1)

def fetch_sha256_from_vt(vt,md5_list,export):
    
    initlist = open(md5_list, 'r')
    
    ### Dedup md5 list to reduce query time
    final_list = list(set(initlist))

    ### CLosing MD5 list
    initlist.close


    for md5 in final_list:
        print(md5)   
        ### Stripping \n from each MD5. 
        md5 = md5.rstrip("\n")
        print(md5)    
        ### try/except implemented because if no record is returned from virustotal the loop errors
        try:
            report = vt.get(md5)
            report.join()
            assert report.done == True 
            print "SHA256 is", report.sha256
            sha256_list.append(report.sha256)
        except AttributeError:
            continue
    


    ##Begin second loop to write the SHA256 hashes to a text file
    export = export.rstrip("\r")
    f = open(export, 'w+')
    

    for hash in sha256_list:
        f.write("%s\n" % hash)

    ### Closing SHA256 list
    f.close



fetch_sha256_from_vt(vt,md5_list1,export)












    





    



