
rule m2377_1ab59cc1c4000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.1ab59cc1c4000932"
     cluster="m2377.1ab59cc1c4000932"
     cluster_size="9"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script trojandownloader"
     md5_hashes="['167ec3b5fa6ac7717bf33a31114ba8f2','26f5ddd8e19511c280589181c9e1c297','eadcf0aee8eeb7c6cfe26e5c5be6c04a']"

   strings:
      $hex_string = { 3d22636f707974657874223e436f707972696768742026233136393b2032303137205361626f72205a756c69616e6f2e20546f646f73206c6f73206465726563 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
