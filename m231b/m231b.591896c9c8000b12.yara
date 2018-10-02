
rule m231b_591896c9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.591896c9c8000b12"
     cluster="m231b.591896c9c8000b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker script clicker"
     md5_hashes="['bcf2d82e2b6dae7afb2d29fb02c78b0cd2082f5b','53c2001a936c54c89a05a723920ee0e4d5ab8901','2ae544a74f11d5cd97fd83b4cbda01457475df91']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m231b.591896c9c8000b12"

   strings:
      $hex_string = { 747970653d22636f6c6f72222064656661756c743d2223353835383538222f3e0a3c5661726961626c65206e616d653d227769646765742e6c696e6b2e766973 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
