
rule n2319_39145cc1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.39145cc1c8000b12"
     cluster="n2319.39145cc1c8000b12"
     cluster_size="65"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinhive"
     md5_hashes="['f5bd27d69252613988f44d08562902d644448403','be3fb74e0b26a93f0d74037ad47ed4f66abf6191','2ddcca318fd2f0ab3a2e8c40bf0b8cd2db450ae5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.39145cc1c8000b12"

   strings:
      $hex_string = { 434f4e4649473d7b4c49425f55524c3a2268747470733a2f2f636f696e686976652e636f6d2f6c69622f222c41534d4a535f4e414d453a22776f726b65722d61 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
