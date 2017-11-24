
rule n2321_5b9d6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.5b9d6a48c0000b12"
     cluster="n2321.5b9d6a48c0000b12"
     cluster_size="77"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['045f845565e99ae493f0e3948682783e','0809807da1bea8c3ea42dfc0071c38d5','459f675c0a0faf4cef6609271fa77b55']"

   strings:
      $hex_string = { 11dbe2f2d5d97cb41f5098cd436bcfc7df208b6f67824128de09325a70aaee165b0dc3b2fe22215d88e636f6c2aca4563fdafaa87103ccfb746c42517983e068 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
