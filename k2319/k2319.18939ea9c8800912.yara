
rule k2319_18939ea9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18939ea9c8800912"
     cluster="k2319.18939ea9c8800912"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['b0b66bf63f6e0a983eac6703ba3684021e597655','7fcaab043c9e3f35a1fc85d228590bb9002403f1','71e9c21a3c52c651351ec6debb4b74d98eb47e20']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18939ea9c8800912"

   strings:
      $hex_string = { 6566696e6564297b72657475726e204e5b525d3b7d76617220483d282834392e2c312e3033314533293e3d307846433f2830783144312c307863633965326435 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
