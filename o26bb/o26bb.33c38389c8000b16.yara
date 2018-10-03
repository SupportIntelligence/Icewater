
rule o26bb_33c38389c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.33c38389c8000b16"
     cluster="o26bb.33c38389c8000b16"
     cluster_size="1012"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="downloadsponsor malicious unwanted"
     md5_hashes="['938229f3732e58a43a270dba98b267cb0363c33a','4a2299a7015fed961ffff54fd6aaeba04bb0b26b','3e115273559e83f1923639f181b2833a707fee98']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.33c38389c8000b16"

   strings:
      $hex_string = { 1b104996515a5d4e32164d7f22dc856b82ec1a751572b0d45e94e68055b23c5bc186d1c626c2cf27adea34180cb6442b1c84f0d7bca3178b25130881c99ccc69 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
