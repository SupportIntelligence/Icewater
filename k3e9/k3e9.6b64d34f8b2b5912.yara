import "hash"

rule k3e9_6b64d34f8b2b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f8b2b5912"
     cluster="k3e9.6b64d34f8b2b5912"
     cluster_size="57 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['b7aeb9e12510f0d233bc4fdf69413696', 'aab4492220bcc3b6b65a180f4d13f20e', 'a81522af101db6b05833ce2228d9b607']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5144,1036) == "bed4364ceb3d7a678c6b4e1366c04d45"
}

