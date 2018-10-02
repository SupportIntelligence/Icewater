
rule m2319_2b0d16c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b0d16c9c8000b12"
     cluster="m2319.2b0d16c9c8000b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinhive miner coinminer"
     md5_hashes="['7d70a9baeeb62a28890a97e0ac1cba4e7484a4d0','e4f26c83a3009b52aeb039ef9aa1332029385ac9','dedd07aa2e4b18c3666609f7f07263ff197f4971']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.2b0d16c9c8000b12"

   strings:
      $hex_string = { 3332306531293b7d2c2769734c696e6b273a66756e6374696f6e285f3078613836356366297b766172205f30783362643766323d746869735b5f307835376134 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
