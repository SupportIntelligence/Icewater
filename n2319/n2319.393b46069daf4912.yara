
rule n2319_393b46069daf4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.393b46069daf4912"
     cluster="n2319.393b46069daf4912"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner coinminer coinhive"
     md5_hashes="['e11e8ce2110550c2922fc76a583be2e3b6de276e','76f9a0e8a56f3c25724acc855b74bb2d238bb30b','d06d3544419f9c46aa6e29ca4ed5dac1d86c1523']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.393b46069daf4912"

   strings:
      $hex_string = { 3d224142434445464748494a4b4c4d4e4f505152535455565758595a6162636465666768696a6b6c6d6e6f707172737475767778797a30313233343536373839 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
