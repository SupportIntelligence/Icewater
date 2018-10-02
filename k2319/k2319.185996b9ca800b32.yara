
rule k2319_185996b9ca800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.185996b9ca800b32"
     cluster="k2319.185996b9ca800b32"
     cluster_size="50"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e3e79d461ccb10a177f5dd312a8c3db8f1986480','d10004091399482079b3b7504be97a2a7971903d','ada0be6b0e05fbe847609fe6d018a88894b4dd47']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.185996b9ca800b32"

   strings:
      $hex_string = { 756e646566696e6564297b72657475726e20475b535d3b7d76617220423d2828312e343645322c30783136293c3d35333f2836382e3745312c30786363396532 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
