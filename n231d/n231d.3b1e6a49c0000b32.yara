
rule n231d_3b1e6a49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.3b1e6a49c0000b32"
     cluster="n231d.3b1e6a49c0000b32"
     cluster_size="34"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddenapp riskware androidos"
     md5_hashes="['3dc36365af7fa72a768c3323c135efa177f9a013','b11f43e85800b9fd17cac64c4dac76c720149c0a','1343038e9923e164928ed5bcf77661c3cfedc0ad']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.3b1e6a49c0000b32"

   strings:
      $hex_string = { 6018863f73e68c0363bb758d228194019f931270fefc799bd2248820081415174fca11330c8382c242d4ac59132c550909feae5dd8b87123788e835eabc3a953 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
