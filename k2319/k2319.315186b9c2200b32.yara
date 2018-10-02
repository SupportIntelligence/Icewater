
rule k2319_315186b9c2200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.315186b9c2200b32"
     cluster="k2319.315186b9c2200b32"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['020e07e73b6411b16f8720a92db3f01c5db02e44','d3b6eafe95f784619553d8d44395b7a663d19217','4b01a8b1bb0fa3d5d42a9437ff61bf0e3cfb7be0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.315186b9c2200b32"

   strings:
      $hex_string = { 5d213d3d756e646566696e6564297b72657475726e20455b415d3b7d76617220513d2828307843322c362e374531293c3d2830783146352c30783832293f2839 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
