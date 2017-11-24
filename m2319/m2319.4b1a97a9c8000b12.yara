
rule m2319_4b1a97a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.4b1a97a9c8000b12"
     cluster="m2319.4b1a97a9c8000b12"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script html"
     md5_hashes="['3efadea7206224fae9437042160a873e','ade794858353780b690c75c21e9ada2e','ff283a529e98c483cfd62d3181988efc']"

   strings:
      $hex_string = { 4156302f4f59396d383137666d79492f73313630302f494b4c414e2b5345524942552e6769662220626f726465723d223022206865696768743d223135222077 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
