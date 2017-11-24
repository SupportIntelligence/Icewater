
rule m2321_086c63581a9052b3
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.086c63581a9052b3"
     cluster="m2321.086c63581a9052b3"
     cluster_size="107"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cpsg adload riskware"
     md5_hashes="['00292593db1174747b36419bca79e4cc','06fd0bab84fb7776f862e0ce40bb4a3c','2001274ee291ed31c0df83797a2a1171']"

   strings:
      $hex_string = { dcea823be36afba2556d84218ba34043c7b124299ef4a41ba9390eb8440baf63df87e9f15cf99febfd389a3f83e2d7ca93e4e691ef2fa79876737daafff696c3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
