
rule k2319_1e16d99cdb4b4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1e16d99cdb4b4912"
     cluster="k2319.1e16d99cdb4b4912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script crossrider eeaimp"
     md5_hashes="['6960ca94715ae03a47f8603d5ef46bfa4274d096','b148c0dcbf38256c6a2a46827e1e656e40304004','b856babc452ec30166162774390a8a0a8baa1d8d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1e16d99cdb4b4912"

   strings:
      $hex_string = { 3146432c3078314437292929627265616b7d3b766172205834583d7b276a334a273a227572222c27723648273a277572272c276c38273a66756e6374696f6e28 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
