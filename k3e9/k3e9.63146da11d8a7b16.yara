import "hash"

rule k3e9_63146da11d8a7b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146da11d8a7b16"
     cluster="k3e9.63146da11d8a7b16"
     cluster_size="495 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['aa5c80069d5aafc8fcb014c095298fbf', 'aa6b325901add4b67e4ac641eef5cb0d', 'a1c8bf3c43fd5cc5dc24dfeead03a65a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

