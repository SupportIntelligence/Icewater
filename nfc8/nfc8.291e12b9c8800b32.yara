
rule nfc8_291e12b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.291e12b9c8800b32"
     cluster="nfc8.291e12b9c8800b32"
     cluster_size="93"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos wroba"
     md5_hashes="['3e8bbf10dceaf97c224535a3ea3295e1b153a3eb','0758d747170ed18cd3e2b00f23a55c93bdd99217','19e563a10abe1a792fd8de41204ac3509603b7db']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.291e12b9c8800b32"

   strings:
      $hex_string = { 2bac4e6d78d1ba064c086e184fc6b40d80d62df49f8a9d5a47c0ab6b7df319c2fc85a7a8b571565fd70e29b6651c661d52b8df03974915cffa90127a5c232ad5 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
