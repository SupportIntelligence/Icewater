
rule k2319_2b9c9cc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2b9c9cc1c4000b12"
     cluster="k2319.2b9c9cc1c4000b12"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hidelink html script"
     md5_hashes="['1e391f158d62ebe5d777f02a385da244bc02dc8a','1ecdd01dd6ae8d8097d3958eb9f7602c2e22faf4','004ea0f6c1871cc130575a0b7b28cba53d9cc221']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2b9c9cc1c4000b12"

   strings:
      $hex_string = { 343235373739333933313727292c6c3d782e6c656e6774683b7768696c65282b2b613c3d6c297b6d3d785b6c2d615d3b0d0a743d7a3d27273b0d0a666f722876 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
