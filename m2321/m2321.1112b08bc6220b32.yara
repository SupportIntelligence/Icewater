
rule m2321_1112b08bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1112b08bc6220b32"
     cluster="m2321.1112b08bc6220b32"
     cluster_size="36"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shifu shiz banker"
     md5_hashes="['1b8f2f6b97d4f5fe14559b2260f9ef8b','1e3d6a73f5bc7b6d593e50d73ccbff31','75ce341cf17cb71a5dc452f9297b0159']"

   strings:
      $hex_string = { cd781e267df220b385e3392ac5f1af8c96605913ccb9b416bdb83e1bbcf51d374b4a9e01d7ca3139067b4d2dc7d1de5c29d3dc3c65ac8f0e321fc2d9767a46a6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
