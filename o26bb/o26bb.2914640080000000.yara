
rule o26bb_2914640080000000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.2914640080000000"
     cluster="o26bb.2914640080000000"
     cluster_size="59905"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy attribute hacktool"
     md5_hashes="['bd32640c67264f9aabd5ca9d3fce607c20aeb98c','dd8dd77b8694241189e6724178ec8ae1405cbb42','033247ddae9ff13425d4d3623bf075d3911bba19']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.2914640080000000"

   strings:
      $hex_string = { 4e657874446c675461624974656d00df0253686f7757696e646f770000320377737072696e746641000900417070656e644d656e754100c40044726177466f63 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
