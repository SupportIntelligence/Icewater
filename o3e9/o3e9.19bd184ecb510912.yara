import "hash"

rule o3e9_19bd184ecb510912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.19bd184ecb510912"
     cluster="o3e9.19bd184ecb510912"
     cluster_size="2958 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="malicious noobyprotect webalta"
     md5_hashes="['2a7f3e1236d68303499c624fdb4826dd', '050d56543b20a5f3ae3f2cf4c3b92b78', '17fd817c5db67faeeb660809628ae88e']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2519040,1024) == "28017750b5354a3cce1cb6fd5f0e1516"
}

