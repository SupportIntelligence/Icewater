
rule k2319_791696e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.791696e9c8800b12"
     cluster="k2319.791696e9c8800b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['e4c20929798459d9c5e78d8eca7ff02dfc6af37f','f3d70611126d91c4b8bb1d2a26c4d8c6b14725a6','39a6de5625f24049430e7fe10253494f5c046e29']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.791696e9c8800b12"

   strings:
      $hex_string = { 5d213d3d756e646566696e6564297b72657475726e20745b5a5d3b7d76617220643d2828372e393445322c313338293e3d34313f2832362e393045312c307863 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
