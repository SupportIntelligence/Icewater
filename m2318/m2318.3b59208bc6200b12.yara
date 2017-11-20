
rule m2318_3b59208bc6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.3b59208bc6200b12"
     cluster="m2318.3b59208bc6200b12"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['6e24e6bda5400c54710bf8b9dd1e0d8e','b028c41546c73e15ffe4cb92e573e914','ed742e37251f37ebfd892de0ffc08691']"

   strings:
      $hex_string = { 74652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
