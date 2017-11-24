
rule m3e9_531a3949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.531a3949c0000b12"
     cluster="m3e9.531a3949c0000b12"
     cluster_size="11"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus vbkrypt wbna"
     md5_hashes="['176d0969ac4bf5308229c16bf101a583','1982809e3e0e044c7791e1aff64568dd','c239d282f896a6b754f1601d3b387d6a']"

   strings:
      $hex_string = { 94170aefe2928e0bc6a567716f3b1d5e843346c2a79a6c39a27e197344e122d379bff09c4e0e4c04f880284a3597bb831e55b8c341d87f7727b750abe1c9a668 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
