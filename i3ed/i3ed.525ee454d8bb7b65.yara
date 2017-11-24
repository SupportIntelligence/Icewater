
rule i3ed_525ee454d8bb7b65
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.525ee454d8bb7b65"
     cluster="i3ed.525ee454d8bb7b65"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gamarue uztub bundpil"
     md5_hashes="['141dbd25adfdab7379c2fd71d46a54df','aeb043fcd673c7884faacf4e0db868d5','b70dfadc2048a9c7b157a65a8eb12e22']"

   strings:
      $hex_string = { d83b0df4300010731f8b15e83000100355d80fb6023345ec0345fc8b0de8300010034dd88801ebcdff15e8300010817d14007000007505e890fdffff8be55dc2 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
