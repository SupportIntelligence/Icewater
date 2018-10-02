
rule m3f8_4d907941c0000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.4d907941c0000110"
     cluster="m3f8.4d907941c0000110"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos gugi"
     md5_hashes="['c0aecab044f5fb02fefaf592b71d1f6f763624d3','59b7d57aca45c07a00115e3c33e2c79400d77876','8e6aac2e553c580d741dcee79707857ce5aa6e6f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.4d907941c0000110"

   strings:
      $hex_string = { 6d65000867657456616c7565000567726f757000016800076861734e657874000868617368436f64650023687474703a2f2f3138352e3131302e3133322e3936 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
