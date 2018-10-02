
rule k2319_3a54eab4895a6b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3a54eab4895a6b12"
     cluster="k2319.3a54eab4895a6b12"
     cluster_size="66"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script aknjt"
     md5_hashes="['c1ca3c5f3f40bb7e8bf0a2092b9d1925bba5579d','68b4014b88561d98c3abdf3d6e4530da743a2c58','34e5b02b8f9c1aa4b108cbceaefdf5ba676e31f1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3a54eab4895a6b12"

   strings:
      $hex_string = { 4a5d213d3d756e646566696e6564297b72657475726e206f5b4a5d3b7d76617220723d282835392e2c39382e304531293e3d28307831372c38362e344531293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
