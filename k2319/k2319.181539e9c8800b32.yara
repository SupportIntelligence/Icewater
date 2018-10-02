
rule k2319_181539e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181539e9c8800b32"
     cluster="k2319.181539e9c8800b32"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5ddd601f59d8aeaac35704e9696a8a9f5cb94536','411e612d73905785af68b4e8ff920cc9f0895841','17c71d311ec109f0e2a56d85c81dd5e9b05e3239']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181539e9c8800b32"

   strings:
      $hex_string = { 6566696e6564297b72657475726e20515b555d3b7d76617220793d282830783141322c3132312e394531293c32323f2835332c3433323030293a2838372c372e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
