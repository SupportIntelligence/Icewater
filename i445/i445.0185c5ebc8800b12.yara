
rule i445_0185c5ebc8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.0185c5ebc8800b12"
     cluster="i445.0185c5ebc8800b12"
     cluster_size="5"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dorkbot autorun jenxcus"
     md5_hashes="['18b82db1f82cf569e99fbd2bf502b26a','19c4ffd2b60c20689ed90b709b60adb1','abc0f671146bf530726ae2fba7705c99']"

   strings:
      $hex_string = { 1f50e04fd020ea3a6910a2d808002b30309d19002f433a5c000000000000000000000000000000000000003c0031000000000000000000100077696e646f7773 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
