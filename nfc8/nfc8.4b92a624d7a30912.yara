
rule nfc8_4b92a624d7a30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.4b92a624d7a30912"
     cluster="nfc8.4b92a624d7a30912"
     cluster_size="145"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dedc nymaim kryptik"
     md5_hashes="['cac7737e372673fab20caecc0c2f0f1a3c4df7e9','5e5f56536d2e415e9994b0df502cd34121c66255','2e562afd2643a4423ddbf311bb7e59d2d278ba6f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.4b92a624d7a30912"

   strings:
      $hex_string = { 0b84288ee72a1bd56a0c0ea25c0a94eb9da749afd7ed64c278408bc6f1981237a9f6772e7fd66c7d2481081c3caa3ad6dcc7fea0eeec58e8e3473b824a44c113 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
