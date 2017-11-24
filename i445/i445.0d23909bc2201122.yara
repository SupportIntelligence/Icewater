
rule i445_0d23909bc2201122
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i445.0d23909bc2201122"
     cluster="i445.0d23909bc2201122"
     cluster_size="4"
     filetype = "MS Windows shortcut"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dorkbot dobex jenxcus"
     md5_hashes="['0252362464ba356b74ac85725a0f7f83','6d384999770d91d7d5fda466ec793af3','ec4d65a89f890afd90b3551395afcb99']"

   strings:
      $hex_string = { 2e0064006c006c0014030000010000a025414c4c555345525350524f46494c45255c2e2e5c2e2e5c77696e646f77735c73797374656d33325c636d642e657865 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
