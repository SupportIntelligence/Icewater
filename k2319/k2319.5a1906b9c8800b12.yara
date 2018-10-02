
rule k2319_5a1906b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a1906b9c8800b12"
     cluster="k2319.5a1906b9c8800b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['87626f1280b07492c0fc44f10db312132f6b287e','c27851dfaa4743b0ef6f53224537ce4dfe7fc353','bfafa230c6c38f3d787807f589621bd40f4fecc7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a1906b9c8800b12"

   strings:
      $hex_string = { 66696e6564297b72657475726e20455b4a5d3b7d766172204f3d2828307843422c312e313430304533293c2837302e363045312c3235293f2754273a28332e38 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
