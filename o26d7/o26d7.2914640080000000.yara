
rule o26d7_2914640080000000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d7.2914640080000000"
     cluster="o26d7.2914640080000000"
     cluster_size="60168"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy attribute hacktool"
     md5_hashes="['e3349385b9310639378e131a32434b25220064fc','8aa67e1c1b10f600c7d96b272f9e266b2c4a3e5f','849d91998fed212e6e7814ee31420c9e1578a95a']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d7.2914640080000000"

   strings:
      $hex_string = { 4e657874446c675461624974656d00df0253686f7757696e646f770000320377737072696e746641000900417070656e644d656e754100c40044726177466f63 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
