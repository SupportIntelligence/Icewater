
rule m2377_39543949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.39543949c0000b12"
     cluster="m2377.39543949c0000b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script trojandownloader"
     md5_hashes="['0506d9bd8b2d8fc0f75bbf26a184d99f','26895ae7d09ee4b16fab9ccbddd417b0','bab8640dc9ae8d2d9ebaa9659b5a7d70']"

   strings:
      $hex_string = { 3d22636f707974657874223e436f707972696768742026233136393b2032303137205361626f72205a756c69616e6f2e20546f646f73206c6f73206465726563 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
