
rule k2319_18599cb9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.18599cb9c8800b32"
     cluster="k2319.18599cb9c8800b32"
     cluster_size="59"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['5f5f0e9e738318cf8d52d60ad437b13a712020e4','60e3aa7dc9e9551e8b0e6a0d60685d2b5ba70596','e8e456921d601a9678535a04a66c06847f4f34da']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.18599cb9c8800b32"

   strings:
      $hex_string = { 646566696e6564297b72657475726e20475b535d3b7d76617220423d2828312e343645322c30783136293c3d35333f2836382e3745312c307863633965326435 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
