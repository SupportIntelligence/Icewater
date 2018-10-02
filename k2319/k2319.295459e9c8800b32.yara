
rule k2319_295459e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.295459e9c8800b32"
     cluster="k2319.295459e9c8800b32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['11e2ae0f07c7a64112f625457802127bfc8b6b5d','414297e7cc880694a77ec11c921fc7fc1905df50','c5e4b038c7e0daba8d34b98a06f57625fbcf552f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.295459e9c8800b32"

   strings:
      $hex_string = { 213d3d756e646566696e6564297b72657475726e20745b765d3b7d76617220543d28283134392e2c32352e354531293c3d33352e3f28307844462c227922293a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
