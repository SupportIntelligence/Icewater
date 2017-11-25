
rule m2319_3b513949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3b513949c0000b12"
     cluster="m2319.3b513949c0000b12"
     cluster_size="7"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script trojandownloader"
     md5_hashes="['34e72ef190b10028df370913ae053d86','3727b0cd2a23ecd99216b90adb8790c8','d00de3973fbf26e4f4c33fbd96ef9b1d']"

   strings:
      $hex_string = { 3d22636f707974657874223e436f707972696768742026233136393b2032303137205361626f72205a756c69616e6f2e20546f646f73206c6f73206465726563 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
