
rule k2319_59161ce9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.59161ce9ca000b32"
     cluster="k2319.59161ce9ca000b32"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['c48c954d795696d11c8f21d25ed18f7d32891d41','8c26de04d5f1e730b3d023be9fff39aedb556150','573fd2238a054811d74768d442142b552e74d859']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.59161ce9ca000b32"

   strings:
      $hex_string = { 31364533293f30783144343a2830783234432c39342e374531292929627265616b7d3b766172204836583d7b27733933273a226f6e222c27543733273a22797a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
