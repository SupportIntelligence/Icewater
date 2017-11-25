
rule m3f7_59b92007012b4993
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.59b92007012b4993"
     cluster="m3f7.59b92007012b4993"
     cluster_size="3"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['ba3f1b74e3afe0ab0bd9f6241d198e7b','d4866da03ed20cc8dabd883170686b69','d4c97122b3fd730b1df4aee9e3828685']"

   strings:
      $hex_string = { 8580373f6d3fde8f4eb79f59c3a47ceb604ddfc9055f6b878d22672c3fe3560e2f16413c5e75f45b3f63b676b56886780399a3088476d6968e92888d0d1e7925 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
