
rule o26bb_33bd1149c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.33bd1149c0000b12"
     cluster="o26bb.33bd1149c0000b12"
     cluster_size="3616"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi malicious hacktool"
     md5_hashes="['b2b09bf201e1d43952d55f687a721bc3dfe7b595','48c343b76119946c7a19b57950542a2c3eaaad0b','ef673fee5f29b3f9bc43f5c23ec77836ed6d969e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.33bd1149c0000b12"

   strings:
      $hex_string = { 2406c30fe82e7fffffeb01b085c00f842c000000f87301b7f97201bd5156579cfc33f68775088b7d0c8b3f8b07406bc00403f88b4d1066f3a5ff45089d5f5e59 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
