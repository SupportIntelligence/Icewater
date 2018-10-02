
rule j26bf_29386a0080001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.29386a0080001132"
     cluster="j26bf.29386a0080001132"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy kryptik ezgokt"
     md5_hashes="['4218ab82d2bcd145e0ba3237ea7021503a59b643','f195a0b3a9cc636887736a1b233a4ec193c45e81','f69ada7496493792c90a8907f535ba247519b2c7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.29386a0080001132"

   strings:
      $hex_string = { 08b77a5c561934e0890320000102060e0600011d051d0508b03f5f7f11d50a3a0600011d05120903061d05030000010600031818181805000209181805000218 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
