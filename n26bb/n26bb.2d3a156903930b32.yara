
rule n26bb_2d3a156903930b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.2d3a156903930b32"
     cluster="n26bb.2d3a156903930b32"
     cluster_size="1808"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious spigot unwanted"
     md5_hashes="['7e42bae8859c7977689e1b83b7a983ecd782bfae','84b67304f2e1a86bcd98330e6c23b4cfc8a0ffd2','980cb93172dee42752a991537017a2613344d688']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.2d3a156903930b32"

   strings:
      $hex_string = { 483bd87d318b549e0485d2750433c9eb188bca8d79020f1f4000668b0183c1026685c075f52bcfd1f951528d8dacfaffffe8f4bbfeff681cba4700ff349ee8db }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
