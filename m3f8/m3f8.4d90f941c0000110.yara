
rule m3f8_4d90f941c0000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.4d90f941c0000110"
     cluster="m3f8.4d90f941c0000110"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos gugi"
     md5_hashes="['1943f4b4d16c94185166758a2085b746afcaa0b4','c9537f6acea7e1a51b7777b1762772fd873e3c95','38755ecafe2260bbf73777ffc600a5eb99cc29d6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.4d90f941c0000110"

   strings:
      $hex_string = { 54696d65000867657456616c7565000567726f757000016800076861734e657874000868617368436f64650023687474703a2f2f3138352e3131302e3133322e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
