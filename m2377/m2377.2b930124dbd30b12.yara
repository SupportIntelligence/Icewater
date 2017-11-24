
rule m2377_2b930124dbd30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.2b930124dbd30b12"
     cluster="m2377.2b930124dbd30b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['73826e6ff446eaa90281eefa495e9b77','ba13a9d25a58903ca21b2ad270e9ae67','f790c1c2c457d58a89bb0ee1fbf8179f']"

   strings:
      $hex_string = { 6d344264772d762d4359772f554773695f647256796e492f4141414141414141577a452f46575f6850786b746252672f7337322d632f3130342e6a7067272077 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
