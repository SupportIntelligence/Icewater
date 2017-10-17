import "hash"

rule n3ed_0ca3390f1a12d132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.0ca3390f1a12d132"
     cluster="n3ed.0ca3390f1a12d132"
     cluster_size="140 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['a258c84c0ff5319bb4596c06f73dff6a', '3058d976ae8cf251239b1550dba58edb', 'cd2a748c948d6f9794044425a0e8aa5d']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(573952,1024) == "5ecc66daf37afcd45ee35aa85806cf8c"
}

