import "hash"

rule k3e9_15e14b9a9ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e14b9a9ee311b2"
     cluster="k3e9.15e14b9a9ee311b2"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['c7b9fa2110a7a5d9b565ed3fb03ff500', 'c7b9fa2110a7a5d9b565ed3fb03ff500', 'c7b9fa2110a7a5d9b565ed3fb03ff500']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "2f71af6522927f93cb15efa00c89d5db"
}

