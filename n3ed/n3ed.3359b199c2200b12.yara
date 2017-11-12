
rule n3ed_3359b199c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.3359b199c2200b12"
     cluster="n3ed.3359b199c2200b12"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['0efa112625215f50e160892140bae32f','10dca6db33eb3ac0b1705e642695389e','e3e4530e958fc4e05a8260a96f2454b9']"

   strings:
      $hex_string = { d083c604ebed5ec3568b7424086a00832600ff1530e013216681384d5a75148b483c85c9740d03c18a481a880e8a401b8846015ec3558becb82c120000e8bfce }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
