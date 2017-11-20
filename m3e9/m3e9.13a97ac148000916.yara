
rule m3e9_13a97ac148000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13a97ac148000916"
     cluster="m3e9.13a97ac148000916"
     cluster_size="842"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['004bd0d0a803828c75b3e9effb45675d','004dcb53f2e14f9bd4d463ade56d50f6','0560663bb9260cdc7edde4312bf388e4']"

   strings:
      $hex_string = { 1ac36cc415e99f1d07757782d778922c5039c7a1129819e66bdbffd838bef648b8892d5a6495fa719d18a46a66746ef311704c3f2206f9df5eb6935b854ad9bd }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
