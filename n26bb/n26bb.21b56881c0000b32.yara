
rule n26bb_21b56881c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.21b56881c0000b32"
     cluster="n26bb.21b56881c0000b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="csdimonetize malicious adwarefiletour"
     md5_hashes="['065a035a45e4975de38bc4dcde523242f706574f','476a8214eb04848a54890d8417167125ec09ac32','2ca3b7ef89e9e1ce1366d498f5fb50c489014c2f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.21b56881c0000b32"

   strings:
      $hex_string = { a39d91c8892d9e9925108666344ccb8fc848496804830b17510f0dced511f4e23ce7475e61e6f9631c79f5223182ee05030c6cdcc4ba7b1ea4a77f807367cff2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
