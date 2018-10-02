
rule n2326_591a9aabd8626916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2326.591a9aabd8626916"
     cluster="n2326.591a9aabd8626916"
     cluster_size="77"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="genieo geonei macos"
     md5_hashes="['ce08e4b0c463d646bf1ec238539d9f9317254b6d','3f8d0e558147833efd8deea015f84e71aa8c4156','f12f73b4c9c61ffff718f19611d8c13a68703cdd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2326.591a9aabd8626916"

   strings:
      $hex_string = { f99c0fa896378b3b566bc622eab90ccae45f5e40cbcc6ffbc34dc5ed42461ec9f0bf10d8f5c1e5f2f133f8575d9e1724be00736c20d48f3ae7c4b174ba698a67 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
