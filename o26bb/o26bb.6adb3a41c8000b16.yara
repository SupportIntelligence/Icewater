
rule o26bb_6adb3a41c8000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.6adb3a41c8000b16"
     cluster="o26bb.6adb3a41c8000b16"
     cluster_size="679"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cerbu malicious advgoempq"
     md5_hashes="['f4f496604c9531dd90e77cddb4ba1397219badcf','66be3a9ee363edd370771edb2dac845fedb9f084','a2b5a7f0833723f50b9aa659997392423382f69e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.6adb3a41c8000b16"

   strings:
      $hex_string = { c97405895110eb0389573839473c750885d20f45ca894f3c5f5e5b8be55dc3cccccc558bec83ec085356578bf98d5a1f897dfc83e3e08d770456ff157ce04300 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
