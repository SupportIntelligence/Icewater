
rule o3e9_594a4e669ba30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.594a4e669ba30932"
     cluster="o3e9.594a4e669ba30932"
     cluster_size="55"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['00d149b92533c1715db3ec6d0f53f336','01ed194a3d45c8e26450916f128874b4','575cbb59a8d8fb001f3b509347c9e61b']"

   strings:
      $hex_string = { 002800250064002900110049006e00760061006c0069006400200063006f00640065002000700061006700650008004600650062007200750061007200790005 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
