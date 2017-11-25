
rule o3e9_5986b4cffe630b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.5986b4cffe630b32"
     cluster="o3e9.5986b4cffe630b32"
     cluster_size="126"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious riskware"
     md5_hashes="['03d73c93ad3f8d7c18f86841e9ac031f','04e36612d3f8fd8b4bef708224f1e83d','25bb6b9a4ae7266ee82fa4b1dc3b154a']"

   strings:
      $hex_string = { 2800250064002900110049006e00760061006c0069006400200063006f0064006500200070006100670065000800460065006200720075006100720079000500 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
