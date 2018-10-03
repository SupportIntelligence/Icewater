
rule ofc8_491450d0dec30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=ofc8.491450d0dec30932"
     cluster="ofc8.491450d0dec30932"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware shedun"
     md5_hashes="['2beb9a8833d04bce93f6dd9371681c141d3fc2fe','c8ffea658a9b28f4c0ad62932a79a20f560c249a','f4c1adc3f2e569e63df08ecc116bc347e8efa967']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=ofc8.491450d0dec30932"

   strings:
      $hex_string = { 30ced0f7a35cfa93e3559a7c13c8ef1007deeccd7b965892fb69000ca553e124c18678c63de5df042fcb9d7a50dc9b1c017f02672e656e270dc0db8e423a0e18 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
