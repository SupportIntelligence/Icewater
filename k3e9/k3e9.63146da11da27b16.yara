import "hash"

rule k3e9_63146da11da27b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146da11da27b16"
     cluster="k3e9.63146da11da27b16"
     cluster_size="413 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b75d503d6a698d8b97bb3fe9f65adab1', 'b039fd9d8a3e0a4e49083508ace1286e', 'a78f24cfe4b53cfad787bc4be48cef63']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

