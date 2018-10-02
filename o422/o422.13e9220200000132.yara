
rule o422_13e9220200000132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o422.13e9220200000132"
     cluster="o422.13e9220200000132"
     cluster_size="3112"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="possible adposhel filerepmalware"
     md5_hashes="['9c4747d3427842ed304972f03852162f3c171daf','d9ba714f3de4b6160d4ccd541d712f7c909c110f','9dd30d8b92feddd8d331728e2972a59c2a7c9edc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o422.13e9220200000132"

   strings:
      $hex_string = { fe270971000009710000b93e0000b93e0000f80bfe27cb7a0000cb7a000099e2000099e20000f80bfe27f0b10000f0b100002b8e00002b8e0000f80bfe278fbb }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
