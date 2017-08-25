import "hash"

rule k3e9_6c54fa47ce420b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6c54fa47ce420b14"
     cluster="k3e9.6c54fa47ce420b14"
     cluster_size="2547 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="tinba vbkrypt zusy"
     md5_hashes="['336fcd00d5c5d132a91480472d17dd56', '3c9771dcfda77a63054cd0bc14914cb9', '14170c84e774b0042970d83a82d4eac1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "74503e0079becfbeaf26a37d08723c8a"
}

