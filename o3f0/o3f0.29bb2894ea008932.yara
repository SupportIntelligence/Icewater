
rule o3f0_29bb2894ea008932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f0.29bb2894ea008932"
     cluster="o3f0.29bb2894ea008932"
     cluster_size="104"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious fynx kryptik"
     md5_hashes="['082b4f831247e629a80cd892bd0d012c','09c676564800a65c27a2d4dd4c1cb970','3ca925ad89aba6dbd51f3016f5f9847b']"

   strings:
      $hex_string = { f439f839fc39003a0000083a0c3a103a143a183a0000203a243a200a200a00000000300a3c3a403a443a00004c3a0000543a583a5c3a600a643a683a600a700a }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
