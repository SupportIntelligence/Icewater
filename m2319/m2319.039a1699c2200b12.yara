
rule m2319_039a1699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.039a1699c2200b12"
     cluster="m2319.039a1699c2200b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script embtfc"
     md5_hashes="['01421a5ff5a39c13ab3c286b8f28e0f81bdc3fce','a6657cee0dfe13e949e2bf7281710ec07b01f2f7','8eef785d74630fe050bffd7fadd76a3ff107f6a8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.039a1699c2200b12"

   strings:
      $hex_string = { 20683620613a686f7665727b636f6c6f723a233232327d2e64656661756c742d7374796c6520696e7075745b747970653d227375626d6974225d2c2e64656661 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
