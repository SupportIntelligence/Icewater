
rule k2319_315186b9ca200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.315186b9ca200b32"
     cluster="k2319.315186b9ca200b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['fc2b8c7b45f9036c7626a884bbd6d75427fda157','2fe5250d7f52c5002214fd413bf0629e48932459','ac2816240f3daa7ca73c99b6aab77a1305ab046b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.315186b9ca200b32"

   strings:
      $hex_string = { 5d213d3d756e646566696e6564297b72657475726e20455b415d3b7d76617220513d2828307843322c362e374531293c3d2830783146352c30783832293f2839 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
