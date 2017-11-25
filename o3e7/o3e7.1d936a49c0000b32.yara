
rule o3e7_1d936a49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.1d936a49c0000b32"
     cluster="o3e7.1d936a49c0000b32"
     cluster_size="45"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor itorrent malicious"
     md5_hashes="['00f3e5392624d7060f0ffd6cf4b421cf','026ff813e9ae77fafd8e4a2d0c0351f9','5c93878e737bae0bc1537f14c0c1f195']"

   strings:
      $hex_string = { ff28376e2f06c51aa1aa3d3b9321a60d6a2342e59b251fc14aa45290307f71e446f04548737c14d18018c7deb406859ee3f31d890fe7311cb65759d3d05deeb3 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
