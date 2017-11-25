
rule m3f7_52b92013004b4993
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.52b92013004b4993"
     cluster="m3f7.52b92013004b4993"
     cluster_size="146"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['00244399a3157d7e1c7b378d171b9a8b','00d64f4cc6c9829d51f060ed1c4908ad','1c9b288772a394bb1ac93e283fdd46c1']"

   strings:
      $hex_string = { 8580373f6d3fde8f4eb79f59c3a47ceb604ddfc9055f6b878d22672c3fe3560e2f16413c5e75f45b3f63b676b56886780399a3088476d6968e92888d0d1e7925 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
