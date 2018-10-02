
rule m26bb_53928db484fb4d92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.53928db484fb4d92"
     cluster="m26bb.53928db484fb4d92"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="swisyn malicious attribute"
     md5_hashes="['026a1cc1998a7d413756d32e91d1a9d9797cc642','1b940b4e89042838dfa8c9e7332f2e695ac4f716','ff4a3a603012252419f7ff2c0ac5353b6a09a6ad']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.53928db484fb4d92"

   strings:
      $hex_string = { 8d7d8c6a0ff3a559be4c0600088dbd4cffffff837d0c00f3a566a5bbcc040008752f6844646b2068500100006a00ff15c40200088bf06a545933c08bfe81c6a8 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
