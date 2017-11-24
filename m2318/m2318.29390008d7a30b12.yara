
rule m2318_29390008d7a30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.29390008d7a30b12"
     cluster="m2318.29390008d7a30b12"
     cluster_size="21"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0bdc6b0b0fceb540d95c58b10a459577','0ef45a2823275141f7f7808c961030bb','c663de40b111a29199d4935325f96491']"

   strings:
      $hex_string = { 652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e64 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
