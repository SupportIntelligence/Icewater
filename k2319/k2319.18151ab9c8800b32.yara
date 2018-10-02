
rule k2319_18151ab9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18151ab9c8800b32"
     cluster="k2319.18151ab9c8800b32"
     cluster_size="36"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['ef1082d2413107bb59502d0678c3455e0200c4ca','2a86ff715c96b1784ba329401585ae6fb3a06cd7','98a1c94e667bba6ad0bd369c8d546713a4578402']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18151ab9c8800b32"

   strings:
      $hex_string = { 6566696e6564297b72657475726e20515b555d3b7d76617220793d282830783141322c3132312e394531293c32323f2835332c3433323030293a2838372c372e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
