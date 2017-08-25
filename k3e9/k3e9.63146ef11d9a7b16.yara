import "hash"

rule k3e9_63146ef11d9a7b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146ef11d9a7b16"
     cluster="k3e9.63146ef11d9a7b16"
     cluster_size="35 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a592c2f987a7902265083364694ba628', 'a56cd66be39843b80e877c7a7dc8b466', 'cc192e3c3bfd18886ddc67bf94b84fd1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

