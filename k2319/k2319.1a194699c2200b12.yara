
rule k2319_1a194699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a194699c2200b12"
     cluster="k2319.1a194699c2200b12"
     cluster_size="74"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['bc4c43b915460adbd1a4c9588e4cc96ca4806869','ce4e893dac3c30890f3ba6e1afc570aabb15e0cd','7d5cc2bd07c5304a193e897d65bcf1296ef7af44']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a194699c2200b12"

   strings:
      $hex_string = { 39293a28307837352c3078314246292929627265616b7d3b7661722044334337723d7b27773737273a226273222c27433372273a66756e6374696f6e28702c64 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
