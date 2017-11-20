
rule m3e9_53a60c4ed3eb1132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.53a60c4ed3eb1132"
     cluster="m3e9.53a60c4ed3eb1132"
     cluster_size="239"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus jorik malicious"
     md5_hashes="['00cec03a1bcd9c77df902413fc561f2f','05e5e86950b392454c18eea20801e80c','4ee63467d5c5e5f6ced2548549da4528']"

   strings:
      $hex_string = { 616e676557696e646f772e00004e65775f52575f506f70496e74657276616c0000496620547275652c20746865204c4544202e56616c756520646973706c6179 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
