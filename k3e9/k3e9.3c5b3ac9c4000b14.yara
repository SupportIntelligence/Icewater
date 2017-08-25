import "hash"

rule k3e9_3c5b3ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c5b3ac9c4000b14"
     cluster="k3e9.3c5b3ac9c4000b14"
     cluster_size="399 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['614f489a78e612fbba2162bcd1b3b390', 'cab39a55ebeb55b8c7fa0cbec6d44972', 'b4d3ac3582c637a3a06842d0edfd4d07']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(6400,256) == "1371fd7f3206a21874fbe56ff62fb073"
}

