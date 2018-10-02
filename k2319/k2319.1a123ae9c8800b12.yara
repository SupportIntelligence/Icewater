
rule k2319_1a123ae9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1a123ae9c8800b12"
     cluster="k2319.1a123ae9c8800b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['0bfa12cfcb4a8dbd2b23804ce876bd955f49f9ed','b8eb5279efb31ceda4a098373aac95e3f88c71e1','0d270c768f2aa0f6241ac90ddcd563b020a299ae']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1a123ae9c8800b12"

   strings:
      $hex_string = { 552c47297b696628595b475d213d3d756e646566696e6564297b72657475726e20595b475d3b7d766172206f3d282838372e333045312c312e3239354533293e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
