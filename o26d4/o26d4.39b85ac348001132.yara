
rule o26d4_39b85ac348001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d4.39b85ac348001132"
     cluster="o26d4.39b85ac348001132"
     cluster_size="880"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy kryptik adposhel"
     md5_hashes="['f648a18253d275ed497abe9e036110f2c836a8ae','689abd75c735187730af610c595ab061dcdc033b','802e916fb2a2ab1f63e5f329a7aceaf1b143d542']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d4.39b85ac348001132"

   strings:
      $hex_string = { 006fd9024ef0d4e1e22816c263f0d4e1e2e312a25e10d81379f0d4e1e2dcf8ae94f0d4e1e2748726520341a07bf0d4e1e2d8570a23f0d4e1e2bed71cb8c3ea6b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
