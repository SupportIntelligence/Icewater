
rule o26bb_119916c8c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.119916c8c4000b32"
     cluster="o26bb.119916c8c4000b32"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="patched malicious heuristic"
     md5_hashes="['3c5384d2be96ae4326abf96b12c6ce412ef53e44','82fe2d2f0b9a2fdfe1e6304eb9f8a73f0ebdfade','296420fb624dec802b5a119494bb21f4d50a5c1d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.119916c8c4000b32"

   strings:
      $hex_string = { 48f403c851895dfc4350895df0e81d2d0200595933c985c00f95c185c97505e8800d00008a003c5c74103c2f740c0fb64614508bcfe84765f9ff8b068d4dec51 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
