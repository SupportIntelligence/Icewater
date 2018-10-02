
rule n26bb_2d3a5469b1a10b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.2d3a5469b1a10b12"
     cluster="n26bb.2d3a5469b1a10b12"
     cluster_size="2488"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious riskware spigot"
     md5_hashes="['6a1e64527bb662d60ee7365edbfa90eaf48ad375','730890892e575f43610d589813990613fd1517b0','910edd471a94a6f9c2e944b4882c7359f2315d5d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.2d3a5469b1a10b12"

   strings:
      $hex_string = { 483bd87d318b549e0485d2750433c9eb188bca8d79020f1f4000668b0183c1026685c075f52bcfd1f951528d8dacfaffffe8b4bafeff6830e34700ff349ee815 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
