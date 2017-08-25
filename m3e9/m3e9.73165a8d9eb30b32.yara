import "hash"

rule m3e9_73165a8d9eb30b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.73165a8d9eb30b32"
     cluster="m3e9.73165a8d9eb30b32"
     cluster_size="252 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="swisyn mofksys bner"
     md5_hashes="['6c739c4c644479debcea136ac90eec86', 'dfd214dd0149cde6ca80a9042128c6da', '28f5c86925507a7504ee3fc6d81739e2']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(150528,1024) == "446877bb72cb1aac8e4408f2cd169793"
}

