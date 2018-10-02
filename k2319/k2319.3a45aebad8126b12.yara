
rule k2319_3a45aebad8126b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3a45aebad8126b12"
     cluster="k2319.3a45aebad8126b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script aknjt"
     md5_hashes="['7218356eb2c552324ccd7e834f9c6801d8d2cdbc','a2e722df03cd6c5bc2d15832f090f630cfb306e7','5bbaa8fb0f7f24039b2b99b6feaf611b24fa96ef']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3a45aebad8126b12"

   strings:
      $hex_string = { 4a5d213d3d756e646566696e6564297b72657475726e206f5b4a5d3b7d76617220723d282835392e2c39382e304531293e3d28307831372c38362e344531293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
