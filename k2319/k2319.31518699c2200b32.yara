
rule k2319_31518699c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.31518699c2200b32"
     cluster="k2319.31518699c2200b32"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['c9904dc2fd397c4a72f5b8ab08922f131cc03b6c','ab14488b9c20a584410c31adafa1c20efcafc6cd','752cd94dd71b9a963f7b1dec533267e04403961d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.31518699c2200b32"

   strings:
      $hex_string = { 5d213d3d756e646566696e6564297b72657475726e20455b415d3b7d76617220513d2828307843322c362e374531293c3d2830783146352c30783832293f2839 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
