
rule m3f9_139d6a49c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f9.139d6a49c0000b16"
     cluster="m3f9.139d6a49c0000b16"
     cluster_size="9"
     filetype = "MS-DOS executable"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar deepscan pwstealer"
     md5_hashes="['0c5d26f0858668f3c6b9cf8acc16bb35','0e36509ad005fd75c796a3d19379edb2','deafee19ca4c14de1bd31204176d3528']"

   strings:
      $hex_string = { bfd117e0a465dc019fe4872667c3e92d1655fb6acf1a4d71da05c540a7a185c920a875c8f4a582c13014f61d356c283c0b66c0810e3e76aead9238b9dc6157ca }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
