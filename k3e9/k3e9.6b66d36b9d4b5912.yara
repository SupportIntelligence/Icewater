import "hash"

rule k3e9_6b66d36b9d4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b66d36b9d4b5912"
     cluster="k3e9.6b66d36b9d4b5912"
     cluster_size="3 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['be4952095eee5d1d6dd0299cd98e830b', '7c46de783841d591a604b25de098476a', '7c46de783841d591a604b25de098476a']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(13312,256) == "e3ccd7354b1959bf3a96e0f7ffe07981"
}

