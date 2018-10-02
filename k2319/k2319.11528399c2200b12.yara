
rule k2319_11528399c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.11528399c2200b12"
     cluster="k2319.11528399c2200b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e7c4cda2d00fc07a902f674ea124301948f38783','dd033ab715ff62c45763d79e0040d5b7bb4d0f0c','1216f8e2ff464cea3441941a9be8d7e1d9115a13']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.11528399c2200b12"

   strings:
      $hex_string = { 3a2830783233342c31302e384532292929627265616b7d3b7661722054325236753d7b2752304d273a226e73222c27483675273a66756e6374696f6e28512c4b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
