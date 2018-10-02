
rule k2319_181516a9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181516a9c8800b32"
     cluster="k2319.181516a9c8800b32"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['ed00c6c12e515a8ace48cd1ab3b51ee0fec41bfc','d76187cd635cae3ff5c6a1da648b78f8b51b6c7a','73260bce05664f5ad14d1d1e27b84d7d7a83f920']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181516a9c8800b32"

   strings:
      $hex_string = { 646566696e6564297b72657475726e20515b555d3b7d76617220793d282830783141322c3132312e394531293c32323f2835332c3433323030293a2838372c37 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
