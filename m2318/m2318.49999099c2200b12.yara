
rule m2318_49999099c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.49999099c2200b12"
     cluster="m2318.49999099c2200b12"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0118c6e668789866cbec6a4b8932bb1f','16e9871d6643ccea4aea13c1fd51c371','ffa5575c1a45a20079294f73c7183590']"

   strings:
      $hex_string = { 652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e64 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
