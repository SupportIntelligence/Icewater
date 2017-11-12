
rule o3e9_2ca964d97208494e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.2ca964d97208494e"
     cluster="o3e9.2ca964d97208494e"
     cluster_size="98"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious heuristic kryptik"
     md5_hashes="['01add0f2a0c0aa98b0fd904c23c9eda1','0810e4257bdd516ba3dbdefedb89a4a7','2ef4f3d90d4dfcf522e2b7be06c5cac6']"

   strings:
      $hex_string = { 6b41dc8e23038be8878fafd99ff61e35a73e3c31d52662204484d4740e1650dda9ea7d212a15638583576d54f1b1db68fa9acc5eedd3060a0d7fe69b1bef6642 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
