
rule n26bb_2b9e92b9c2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.2b9e92b9c2220b12"
     cluster="n26bb.2b9e92b9c2220b12"
     cluster_size="101"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="incredimail backdoor engine"
     md5_hashes="['6acd3ab6a099ff0d10bbaceec53ce249f49f85ed','11cc525c4cd08f4889e5e3d95990d80d91b06b8b','3a680218cabbaf2da92c587d08a2111187e376c0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.2b9e92b9c2220b12"

   strings:
      $hex_string = { f054a71abfa4c5d4133b67caada8c99178d2feb32e2f61578ae73ce0aabc968c5d41cfece4af52c4ab7c946bef64e6d66d8e1e93bdaec3a0b504432853b179a9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
