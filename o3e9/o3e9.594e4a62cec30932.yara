
rule o3e9_594e4a62cec30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.594e4a62cec30932"
     cluster="o3e9.594e4a62cec30932"
     cluster_size="130"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="strictor dealply riskware"
     md5_hashes="['01e7c51362b0e3767bf520d9e17fc69a','0378b679a85c7513da035a39e3d657e5','141c6bdb3bb5d6564ee7e3edd576aafa']"

   strings:
      $hex_string = { 002800250064002900110049006e00760061006c0069006400200063006f00640065002000700061006700650008004600650062007200750061007200790005 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
