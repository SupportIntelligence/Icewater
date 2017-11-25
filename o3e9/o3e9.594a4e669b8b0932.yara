
rule o3e9_594a4e669b8b0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.594a4e669b8b0932"
     cluster="o3e9.594a4e669b8b0932"
     cluster_size="21"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="strictor dealply malicious"
     md5_hashes="['102cea01a1dc71abc559c74699e66cc9','1ba8c737e9ff44ba50a063715d11c2eb','b912f76581789cad63f0a9962c12faab']"

   strings:
      $hex_string = { 250064002900110049006e00760061006c0069006400200063006f00640065002000700061006700650008004600650062007200750061007200790005004d00 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
