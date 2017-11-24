
rule k2321_4b12b322dee30916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.4b12b322dee30916"
     cluster="k2321.4b12b322dee30916"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['730843eb9c03f40716e4327a01e834c4','beabc191fad6ba4acecfa9059c6eb36c','da8b790066c572c6e3b7fe14735179ca']"

   strings:
      $hex_string = { 12f8713844cee1f0863366caec3526fa0d7493f21598415c4fbc9fee000fd4a357c24e75769e28f3acf0835a361381cf903ecb07d3ef2204cac5b0b9789d483a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
