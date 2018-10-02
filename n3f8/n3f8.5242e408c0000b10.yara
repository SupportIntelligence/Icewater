
rule n3f8_5242e408c0000b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.5242e408c0000b10"
     cluster="n3f8.5242e408c0000b10"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos banker boogr"
     md5_hashes="['e0459369bb0088537673b14a2294082aa8aa4988','c311ebcc4fc76dc1c93a7795132840edf3292101','f3f3c0ffa793d1406895995e6128aa095db0d06c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.5242e408c0000b10"

   strings:
      $hex_string = { 163b20706f7274206973206f7574206f662072616e676500563b5c732a283f3a285b612d7a412d5a302d392d2123242526272a2b2e5e5f607b7c7d7e5d2b293d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
