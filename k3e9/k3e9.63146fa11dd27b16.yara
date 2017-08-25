import "hash"

rule k3e9_63146fa11dd27b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146fa11dd27b16"
     cluster="k3e9.63146fa11dd27b16"
     cluster_size="145 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c9e4c10efe19ec88c4052513557282de', 'a5888b02ef71824b83f20e0c0d1cde8b', 'd051b0d2dddfbc8ba77b3152e1f4f2e8']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

