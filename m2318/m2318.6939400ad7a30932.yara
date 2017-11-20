
rule m2318_6939400ad7a30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.6939400ad7a30932"
     cluster="m2318.6939400ad7a30932"
     cluster_size="24"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['09c3193835b66e64677edc73672bb598','1ba288fca12c4d04e7563f47a1bcbe47','bbaac8213e5f4d11e04c9c54f6f4510e']"

   strings:
      $hex_string = { 74652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
