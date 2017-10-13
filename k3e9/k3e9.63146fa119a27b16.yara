import "hash"

rule k3e9_63146fa119a27b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146fa119a27b16"
     cluster="k3e9.63146fa119a27b16"
     cluster_size="79 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d0a4b6c80de155a79dcb8f2ee5653fb9', '7ccd0e9cf600da8c68ef8cb28b41d535', 'ab9bef4b3ca78e8d9ee5b8e3750851c2']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(28672,1024) == "cbe3f2c767bf3f871e1e15b0008153e1"
}

