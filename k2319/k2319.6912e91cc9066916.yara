
rule k2319_6912e91cc9066916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6912e91cc9066916"
     cluster="k2319.6912e91cc9066916"
     cluster_size="3179"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script flooder html"
     md5_hashes="['6324baa81f167171bf6a7a5e0df38bbc2187df2e','89eaecb1f0398da4ae540e61360c31434163bb00','2250b5ab775a6acb82a75d80ce61e71cb7911c51']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6912e91cc9066916"

   strings:
      $hex_string = { 31466b556775515173443949546d443745435a494a5345344f5a6f3973746f566a432f7a63376b792b7a483968587756774470544157574c7267533351416538 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
