
rule k2319_391296b9ca800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.391296b9ca800b12"
     cluster="k2319.391296b9ca800b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['d26db9921535a6843275a934d6ca3c2f6f9a8529','a8c891f9c51ead58b3d230c8628a7bde9121ab78','a13d704f6b6b2c2b523817fc2804e99bd17ca16c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.391296b9ca800b12"

   strings:
      $hex_string = { 213d3d756e646566696e6564297b72657475726e20445b655d3b7d76617220503d282830783141442c342e36324532293e2830783131312c38322e293f283335 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
