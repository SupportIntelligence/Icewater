
rule o3e9_594e4a62dba30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.594e4a62dba30932"
     cluster="o3e9.594e4a62dba30932"
     cluster_size="94"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply awsli malicious"
     md5_hashes="['0192d6188782a058f04624641e07a1f9','037320457104706c3f096d0d2967032b','3bfca809a54101450201b0bcaef04ad8']"

   strings:
      $hex_string = { 250064002900110049006e00760061006c0069006400200063006f00640065002000700061006700650008004600650062007200750061007200790005004d00 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
