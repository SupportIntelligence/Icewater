
rule n231d_3b1e6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231d.3b1e6a48c0000b12"
     cluster="n231d.3b1e6a48c0000b12"
     cluster_size="311"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hiddenapp riskware androidos"
     md5_hashes="['734b37497a089afbddbeb8bedcdbcb93ee6b77c0','341abfd91e1dba613f4a3e4ada29948d88ef30cc','0c29879b9fe3760379ccc1b21102769449b6cf46']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231d.3b1e6a48c0000b12"

   strings:
      $hex_string = { 6018863f73e68c0363bb758d228194019f931270fefc799bd2248820081415174fca11330c8382c242d4ac59132c550909feae5dd8b87123788e835eabc3a953 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
