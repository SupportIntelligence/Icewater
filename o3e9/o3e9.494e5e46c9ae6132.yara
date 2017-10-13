import "hash"

rule o3e9_494e5e46c9ae6132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.494e5e46c9ae6132"
     cluster="o3e9.494e5e46c9ae6132"
     cluster_size="1396 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="delf bancteian reconyc"
     md5_hashes="['2ebca5edf9e8490bf5ec8ceda2d18c0c', '3595e0fc44b5997c60c35a6b253804cb', '21e1c3ebf6ed5dc77a8f7757ceec1e42']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2648833,1109) == "8b3b244ae19867d0360498775f80ac63"
}

