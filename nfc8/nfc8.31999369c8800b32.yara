
rule nfc8_31999369c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.31999369c8800b32"
     cluster="nfc8.31999369c8800b32"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos origin"
     md5_hashes="['52e4add28a440611c1e05223b271036054b18aa7','e6259258e20479ee4531fda5cea9b35e2d184f1d','c312d6127039eb3e75be23c85d385f9ac0ded612']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.31999369c8800b32"

   strings:
      $hex_string = { 52deedd6addb5a168be5a7cd892ee6fe0f31bc4d28ae7b4c2cf34ee710ac085e0a57336762993b6577b1267e3dee94a53ef7ff13ba8d4364f03230e80c129fa8 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
