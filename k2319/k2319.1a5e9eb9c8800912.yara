
rule k2319_1a5e9eb9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a5e9eb9c8800912"
     cluster="k2319.1a5e9eb9c8800912"
     cluster_size="38"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script kryptik diplugem"
     md5_hashes="['8fec7ec07c08810b3f4d95b937ca079ae1e3a829','4001774d24b1800620f784ded34a25ded96da320','5b29a04a5639d3f594150494989b9efbd8524927']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a5e9eb9c8800912"

   strings:
      $hex_string = { 3139293a2830783230412c3132372e374531292929627265616b7d3b7661722076364e31763d7b2752366e273a226a222c274f3576273a66756e6374696f6e28 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
