
rule o3ed_419496a8ddeb5b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.419496a8ddeb5b12"
     cluster="o3ed.419496a8ddeb5b12"
     cluster_size="70"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul patched"
     md5_hashes="['003a0be547d49e8db969017a6d47854c','01e312c1457718f54567c3c726f45fda','0fa149b801286157853e803f2807c10f']"

   strings:
      $hex_string = { 8b387a399f3aa53ac03a7f3b9e3ca63cb93c693d6f3dbe3ec73ecd3e00f010006c0000009531d031033273328733dd33a734ff347c35d9366d3796372e384a39 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
