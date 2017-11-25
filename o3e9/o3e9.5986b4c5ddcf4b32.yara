
rule o3e9_5986b4c5ddcf4b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.5986b4c5ddcf4b32"
     cluster="o3e9.5986b4c5ddcf4b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['67f2a8549875f0a9039439d7cbf91cbb','6a607a8ffef1849e0455aeba4b3bee08','720c00e7eae0f071273694101c391e0e']"

   strings:
      $hex_string = { 002800250064002900110049006e00760061006c0069006400200063006f00640065002000700061006700650008004600650062007200750061007200790005 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
