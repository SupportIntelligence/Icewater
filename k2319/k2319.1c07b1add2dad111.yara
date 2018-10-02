
rule k2319_1c07b1add2dad111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.1c07b1add2dad111"
     cluster="k2319.1c07b1add2dad111"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script asmalwsc"
     md5_hashes="['0f09bc9a11abd240db9f68833ce172796aa6f4b7','06fe58582632854b91a2cc814862967eb7d780df','29999d286d039c0912423e797ecf45631fd0448b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.1c07b1add2dad111"

   strings:
      $hex_string = { 6e646566696e6564297b72657475726e204f5b755d3b7d76617220723d28307832313c3d28312e32313945332c3078314341293f28372e393645322c30786363 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
