
rule k2319_1a5e96b9c9000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a5e96b9c9000912"
     cluster="k2319.1a5e96b9c9000912"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script kryptik diplugem"
     md5_hashes="['d3b4c73f2d547573c1f46c2d03a7c8a0d45804d6','1f9327ad588d0c6a70385bba2fd12f386ccf7aed','63d98e4321c7d285b8d52bcfa033f0d51218a712']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a5e96b9c9000912"

   strings:
      $hex_string = { 3139293a2830783230412c3132372e374531292929627265616b7d3b7661722076364e31763d7b2752366e273a226a222c274f3576273a66756e6374696f6e28 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
