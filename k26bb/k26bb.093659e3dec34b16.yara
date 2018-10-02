
rule k26bb_093659e3dec34b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.093659e3dec34b16"
     cluster="k26bb.093659e3dec34b16"
     cluster_size="130"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious unwanted"
     md5_hashes="['c36c9349697eccb6e7b5e7f56a2f971de986bbc8','599696039da14f1951a9b3d793b11997696a030b','11e126ec072e144355fd02b003d5581df0658b0e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.093659e3dec34b16"

   strings:
      $hex_string = { 40ec85c075de5aeb1b8a1a8a4e06ebe88a5c0e06321c0a80e3df75ed4975f18b065a01d05f5e5bc3525153ff50f431d28d4c2410648b1a8919896908c74104ed }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
