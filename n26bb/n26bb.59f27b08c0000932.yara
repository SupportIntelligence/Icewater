
rule n26bb_59f27b08c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.59f27b08c0000932"
     cluster="n26bb.59f27b08c0000932"
     cluster_size="153"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="elemental malicious elementa"
     md5_hashes="['1af83a3248ed3e3a94f53b02c2047e92e84798a8','ed1f7c62e74855ec7673b7c3770b849c65ef4b66','1ba4e07e99e95dca1cbd0bddf90184543f348c71']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.59f27b08c0000932"

   strings:
      $hex_string = { 68785c42005056e88a77ffff83c40c85c075768d4e02397d147403c606458b55188b420c803830742d8b52044a7906f7dac646012d6a645b3bd37c088bc299f7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
