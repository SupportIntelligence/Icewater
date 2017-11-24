
rule k3e9_2b54e945264548b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b54e945264548b2"
     cluster="k3e9.2b54e945264548b2"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba crypt emotet"
     md5_hashes="['43af5d6ff136cfbd37b3b9aed93d1e18','88aee2e8a76fe7f0b1826fc341f1258e','d87cd14816c8ed60df701ed99add666b']"

   strings:
      $hex_string = { ca107c22f7c0d13e653331f0c540ff7d41a776d79c44cc6a86fe47d5267a7220be48c99d611be96bafedcbb28c50f6c1cf4f87664e3add77c73c17cb6dd65b2a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
