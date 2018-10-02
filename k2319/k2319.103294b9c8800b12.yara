
rule k2319_103294b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.103294b9c8800b12"
     cluster="k2319.103294b9c8800b12"
     cluster_size="56"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b491e5989e5de348bdae9b1b9bde51ea71b16397','6d0c5e0c7493660222a35e36731676cfabb6d07b','4f5c2dc7a98dab473c1ceccad183e6a917e57db3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.103294b9c8800b12"

   strings:
      $hex_string = { 3a2835322e393045312c30783337292929627265616b7d3b7661722066327333793d7b27633379273a66756e6374696f6e28562c4a297b72657475726e20567c }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
