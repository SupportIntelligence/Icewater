
rule k2319_5612ea5ad9bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5612ea5ad9bb0912"
     cluster="k2319.5612ea5ad9bb0912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script crossrider"
     md5_hashes="['be47b5e624d8c3672a644c78e8ccf553516713db','16dd57d66f2aacfbfb89dc9abfa58141980873fb','6a8eca494c101d1733a7898882abb10b6268c91e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5612ea5ad9bb0912"

   strings:
      $hex_string = { 283134392e323045312c37382e38304531292929627265616b7d3b766172204f346c36323d7b27523049273a226964222c276c3749273a227064222c274c3347 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
