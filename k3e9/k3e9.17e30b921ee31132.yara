import "hash"

rule k3e9_17e30b921ee31132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.17e30b921ee31132"
     cluster="k3e9.17e30b921ee31132"
     cluster_size="115 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['a7fcb2e2144d4c9ebad7b0cc4113d5dd', 'c291f24755cd4e5eab7edc693159b1f1', '1026642c30dfa002570c0e2898565dd6']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "2f71af6522927f93cb15efa00c89d5db"
}

