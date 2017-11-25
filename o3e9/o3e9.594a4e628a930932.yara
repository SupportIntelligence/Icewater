
rule o3e9_594a4e628a930932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.594a4e628a930932"
     cluster="o3e9.594a4e628a930932"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler awutg"
     md5_hashes="['c52a9807a9cfcfe42033160f3f593ee1','d81d56bcef8f6769411c38ec7dcfd975','e4d1145ff60bbbada70721ba9b0ee803']"

   strings:
      $hex_string = { 002800250064002900110049006e00760061006c0069006400200063006f00640065002000700061006700650008004600650062007200750061007200790005 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
