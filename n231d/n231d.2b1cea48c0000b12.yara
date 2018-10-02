
rule n231d_2b1cea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.2b1cea48c0000b12"
     cluster="n231d.2b1cea48c0000b12"
     cluster_size="730"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos hiddenapp andr"
     md5_hashes="['ece704fe3ce3b1dc8731c550a6dddb6fcebd352e','78e3bef655e0bb0be0cd274ec5b8451ad86b78d3','87835924c29a4285cc37ae9aa4b08b39950300b2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.2b1cea48c0000b12"

   strings:
      $hex_string = { 6018863f73e68c0363bb758d228194019f931270fefc799bd2248820081415174fca11330c8382c242d4ac59132c550909feae5dd8b87123788e835eabc3a953 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
