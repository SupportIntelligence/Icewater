import "hash"

rule k3e9_15e1198a1ee311b2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15e1198a1ee311b2"
     cluster="k3e9.15e1198a1ee311b2"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['b5f0af4ebf8533f1fcbcd7cd1c83a17b', 'cb5334d87a3a629da8c0a0d1126b64f9', 'cb5334d87a3a629da8c0a0d1126b64f9']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,1024) == "2f71af6522927f93cb15efa00c89d5db"
}

