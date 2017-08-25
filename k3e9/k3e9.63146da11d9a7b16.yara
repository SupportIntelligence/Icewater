import "hash"

rule k3e9_63146da11d9a7b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146da11d9a7b16"
     cluster="k3e9.63146da11d9a7b16"
     cluster_size="216 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['bc98e2eb7c5751140c26dfed0c1d6110', 'c87920ae0e57822b08a2fff54a1b4d74', '101e23c19bf71c40a5914748fc4b96e2']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

