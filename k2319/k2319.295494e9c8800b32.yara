
rule k2319_295494e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.295494e9c8800b32"
     cluster="k2319.295494e9c8800b32"
     cluster_size="11"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['a9c6b61a0477c90dd7ac98a9ad5c33fc9a20fee8','147a2198ac2b26d5076cd7055ee6a7f85c35e24e','be2c3a849420a66479be517485f59c32d5784c70']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.295494e9c8800b32"

   strings:
      $hex_string = { 646566696e6564297b72657475726e206c5b515d3b7d76617220573d282830783144332c322e34314532293e3d283132362e2c312e3434374533293f3330303a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
