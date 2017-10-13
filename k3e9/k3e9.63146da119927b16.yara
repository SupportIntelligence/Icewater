import "hash"

rule k3e9_63146da119927b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146da119927b16"
     cluster="k3e9.63146da119927b16"
     cluster_size="456 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['affbf3e4a403e26f6ebb1b1e86fd9cd5', '6d39cdbb6f1ead26b2a75028bf3f96f2', 'bf5f7da4e3c537b0006d70ad8f8fbad1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

