import "hash"

rule k3e9_63146da11d8a6b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146da11d8a6b16"
     cluster="k3e9.63146da11d8a6b16"
     cluster_size="481 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b7d173258acfb572db729607818c46d4', 'b2bd6aad5487cce779a7baaf9fce1f88', 'a9e53f08c9404c8a2e0a3fd4c67d3a55']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

