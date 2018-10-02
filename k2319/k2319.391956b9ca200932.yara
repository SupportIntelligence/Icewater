
rule k2319_391956b9ca200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.391956b9ca200932"
     cluster="k2319.391956b9ca200932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5242f8e5c62e5536d891810cae57a3a0681d858c','506e76003eea967da1ca342eacdbaf420a54feb1','f2f2cdaa8d3185628949c212018b2b4a1c5d4124']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.391956b9ca200932"

   strings:
      $hex_string = { 45323f283131312c313139293a28307842422c34292929627265616b7d3b7661722047344a35633d7b27453665273a2243222c27673663273a66756e6374696f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
