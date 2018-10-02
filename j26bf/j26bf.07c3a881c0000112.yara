
rule j26bf_07c3a881c0000112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.07c3a881c0000112"
     cluster="j26bf.07c3a881c0000112"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo tsklnk eyvguz"
     md5_hashes="['c9a74726aa1e95c3a4b8330036e9928dced55d04','1600513764f3c224c07996d45212099197f6bdb1','d203cc1b9fbfbf55c91518c13b3a560cff049fe0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.07c3a881c0000112"

   strings:
      $hex_string = { 417373656d626c7946696c6556657273696f6e4174747269627574650053797374656d2e52756e74696d652e496e7465726f70536572766963657300436f6d56 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
