
rule k2319_18559cb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18559cb9c8800b12"
     cluster="k2319.18559cb9c8800b12"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['9df363ad6b9caf8a36c5752c7f97d94d311271b3','7ebcbbe351a8359ae924a45abe98dcd660105432','c87d32ed557d94c5ac07eb53da5495681c603603']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18559cb9c8800b12"

   strings:
      $hex_string = { 575b555d213d3d756e646566696e6564297b72657475726e20575b555d3b7d766172204c3d282832352c3078313743293e2830783234362c31312e394531293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
