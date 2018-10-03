
rule k2319_18099ea9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18099ea9c8800912"
     cluster="k2319.18099ea9c8800912"
     cluster_size="35"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script kryptik diplugem"
     md5_hashes="['c90a9bc775ecad51ed81fc2b8b9864c2fd102167','3e4c5e0eb76a94ca6d0ddd032a4fddcc4db98d30','2f79ab22bdf93346def7df58fbdf68815aef457d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18099ea9c8800912"

   strings:
      $hex_string = { 66696e6564297b72657475726e204e5b505d3b7d7661722075393d2828307842372c3078313638293c3d34372e3645313f28312e31353145332c307863633965 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
