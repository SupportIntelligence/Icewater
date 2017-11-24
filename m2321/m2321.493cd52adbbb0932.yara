
rule m2321_493cd52adbbb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.493cd52adbbb0932"
     cluster="m2321.493cd52adbbb0932"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['49c498759478c0d73bd16fe098612a35','5e4a186f799afea21fbd99421bfcba3a','fc6786841e31d3c000f53fe88e3298ad']"

   strings:
      $hex_string = { a3f1ca07db616549c7435ab925233e0d5cc9a8f9a460143324c57453a942d23276c04c486e380a19211cd4fd94e38b8c411d36cd3d343befb3cbe9cced44a15b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
