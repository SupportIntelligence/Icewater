
rule o2321_131a00c4c2230932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2321.131a00c4c2230932"
     cluster="o2321.131a00c4c2230932"
     cluster_size="1140"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dinwod nimda deepscan"
     md5_hashes="['0023b370f3d7de98e79c705e6ad7f55c','0025fbb95cc48480946ae5f36a86909e','03d372a6a9a0a306d264a878c7f112ed']"

   strings:
      $hex_string = { 05ae361aa575748492457f87bc6ad6096ff09d5178df9c220b23a6f6d9623a0f9e861b8ed2918194047e6452125369025697fdb6462b9b083218446334cbf520 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
