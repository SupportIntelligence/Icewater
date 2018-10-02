
rule k2319_112596b9ca800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.112596b9ca800912"
     cluster="k2319.112596b9ca800912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e01ccc7e074b29d9385981a292b8e35b10523115','70c5346de6005ac5dfc29e3a1914c253ac74ddee','cfdfea2e591c0a172f2e85cb558f26d624f155b6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.112596b9ca800912"

   strings:
      $hex_string = { 312c30783943292929627265616b7d3b7661722049377031523d7b2764396c273a2263647778222c27463552273a66756e6374696f6e28462c43297b72657475 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
