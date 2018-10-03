
rule i26e2_098394d9c2201122
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i26e2.098394d9c2201122"
     cluster="i26e2.098394d9c2201122"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dorkbot winlnk jenxcus"
     md5_hashes="['bf8bd641db6b7a53d70097814dceec962d34655b','adaf5122edae7c3ad65e8c5526e230dfbdb74a6d','7e01f670fff16c5d503eb584c5097503cef8ad0b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=i26e2.098394d9c2201122"

   strings:
      $hex_string = { 2e0064006c006c0014030000010000a025414c4c555345525350524f46494c45255c2e2e5c2e2e5c77696e646f77735c73797374656d33325c636d642e657865 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
