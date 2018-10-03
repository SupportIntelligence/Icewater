
rule n2726_49591cc1c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2726.49591cc1c8000b32"
     cluster="n2726.49591cc1c8000b32"
     cluster_size="38"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi stantinko malicious"
     md5_hashes="['857bcb8b87ebff408c61a6f7fd7f9758540847ea','f90a56c08e6e3b79f922928570e2f362a14a7fda','ef344bead9d8f009805e9532a16de460e3403b30']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2726.49591cc1c8000b32"

   strings:
      $hex_string = { c745f0b62500008b5424088d420c8b4ae433c8e80fe5a0ffb8380b7510e93273fbff90eb61a1002c051041660988600100005eeb510f84dcfcffff8bcee8986c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
