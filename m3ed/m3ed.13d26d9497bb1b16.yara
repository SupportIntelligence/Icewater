
rule m3ed_13d26d9497bb1b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.13d26d9497bb1b16"
     cluster="m3ed.13d26d9497bb1b16"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['75e5c86e1b58f98413b12e2a6d3b7faf','7b04f22d6acf493764543ae26c671954','d2c1461e3299bb1ed7ea73050658f0ea']"

   strings:
      $hex_string = { 4b6423349ac94dc52f2b92eb448cc0ba182584dc4b313d01d95236b246a25a29a881b9f86bcaddf39f95179141a5b102d1ae35d074b4c2fb0c4e0dd311899700 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
