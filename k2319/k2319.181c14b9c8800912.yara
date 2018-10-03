
rule k2319_181c14b9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181c14b9c8800912"
     cluster="k2319.181c14b9c8800912"
     cluster_size="37"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b72755207955a94144ab6ba6205491cc2b93899d','6cee1d100a948178303e8bba249cbd8cfd07cd58','f80bf2e33a829828d72bdeac571c518fe4a6b2bf']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181c14b9c8800912"

   strings:
      $hex_string = { 43422c3078323239293f28307839442c274f27293a28352e3545312c3078314437292929627265616b7d3b766172206b3371313d7b277538273a66756e637469 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
