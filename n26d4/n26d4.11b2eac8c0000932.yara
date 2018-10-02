
rule n26d4_11b2eac8c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.11b2eac8c0000932"
     cluster="n26d4.11b2eac8c0000932"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="barys guildma malicious"
     md5_hashes="['f3acf44aa9998763525aa0de469de5cd88ce170b','6f80f5279f7a583b99487f7111ace9a01a702b37','d111fe02cc9149158b5675481d2d76117ed9e690']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.11b2eac8c0000932"

   strings:
      $hex_string = { 4710014f1089c789cac1e902fcf3a589d183e103f3a45f09db75c65b5f5ec38d4000558bec83c4f8538bd8b201a180854100e8033dfeff8945fc33c055680bf5 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
