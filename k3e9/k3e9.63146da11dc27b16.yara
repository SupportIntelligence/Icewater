import "hash"

rule k3e9_63146da11dc27b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.63146da11dc27b16"
     cluster="k3e9.63146da11dc27b16"
     cluster_size="380 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['1abe63e1472a62c9a1469ffb50a650fc', 'cb8b60883aede74aaa0919e7bdce42ef', 'a5d2c9c3b3f1b901b8618ab5ca8ed3c9']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(29184,256) == "2e1e953ff8b0c4afd8a93f50be9aa1f2"
}

