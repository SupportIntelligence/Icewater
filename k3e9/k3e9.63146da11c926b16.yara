import "hash"

rule k3e9_63146da11c926b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146da11c926b16"
     cluster="k3e9.63146da11c926b16"
     cluster_size="156 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['f6c7ab7877a1c4e20de92d77c91a15c7', 'df1b03cfc6a470eb27636ae34fc2c6d6', '3fdf41ff1831122d3896b40fb1775f6b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

