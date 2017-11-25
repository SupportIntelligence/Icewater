
rule o3e9_594a4e62989b0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.594a4e62989b0932"
     cluster="o3e9.594a4e62989b0932"
     cluster_size="54"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply malicious skgfv"
     md5_hashes="['00f6d63519afe86f13ed7da1a3446fec','053e1465b15c5c24fe6b0a5562d3c3a2','2f3b8456627987c79df5e80db0dfc339']"

   strings:
      $hex_string = { 250064002900110049006e00760061006c0069006400200063006f00640065002000700061006700650008004600650062007200750061007200790005004d00 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
