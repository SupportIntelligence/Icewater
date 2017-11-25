
rule m3e9_51a60c4ed3eb1132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.51a60c4ed3eb1132"
     cluster="m3e9.51a60c4ed3eb1132"
     cluster_size="274"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik malicious"
     md5_hashes="['0fbc2f0348a90f481ba2d6c88dbf47db','13214659e1c0a81a09a34e4d7b2bdbc6','5a04900a50f05079b53ff0e6e2bc00ee']"

   strings:
      $hex_string = { 616e676557696e646f772e00004e65775f52575f506f70496e74657276616c0000496620547275652c20746865204c4544202e56616c756520646973706c6179 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
