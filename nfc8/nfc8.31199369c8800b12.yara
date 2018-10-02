
rule nfc8_31199369c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.31199369c8800b12"
     cluster="nfc8.31199369c8800b12"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos origin"
     md5_hashes="['ca66987e29461e8add5549b27010fedd130c98c1','b58e6528bc7704229e6ecaf754ffe165cba3705c','ffa7f0d9c8aa5cfbcb7308413b32458e583ec139']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.31199369c8800b12"

   strings:
      $hex_string = { 52deedd6addb5a168be5a7cd892ee6fe0f31bc4d28ae7b4c2cf34ee710ac085e0a57336762993b6577b1267e3dee94a53ef7ff13ba8d4364f03230e80c129fa8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
