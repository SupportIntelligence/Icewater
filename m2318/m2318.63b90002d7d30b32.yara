
rule m2318_63b90002d7d30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.63b90002d7d30b32"
     cluster="m2318.63b90002d7d30b32"
     cluster_size="38"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['00c14dc45f1eb647d048013bec2a13be','02ecbbe58c44c3f6e473ab2c3e293a50','66203b5648a2348155f166917d38fd64']"

   strings:
      $hex_string = { 652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e64 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
