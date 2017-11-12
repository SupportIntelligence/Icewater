
rule m3ed_3b9ac9369abb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3b9ac9369abb1932"
     cluster="m3ed.3b9ac9369abb1932"
     cluster_size="39"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['0065491f69ebc0d74ed40822c4f6d491','083b63d1571303751a1ffb9ce633169b','c14e9f936af05b2431ea621b55a505e8']"

   strings:
      $hex_string = { a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
