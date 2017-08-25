import "hash"

rule k3e9_63146fb11da26b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146fb11da26b16"
     cluster="k3e9.63146fb11da26b16"
     cluster_size="161 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['de6b4e0871745a3f4d9b33d6fd38b40e', 'ce66c1aad3681be9404e7b1eb18280c6', 'bedb3da16d26d20742355a3a5b33c45b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

