
rule n26bb_2b4451a8c10f40b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.2b4451a8c10f40b2"
     cluster="n26bb.2b4451a8c10f40b2"
     cluster_size="726"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="slimware driverupdate unwanted"
     md5_hashes="['cb354a9aebbb1145c22cda530cf9f1796165c2bf','28a0a94461c747cfc4d4883584f554d00f94ca75','68fa2bd826d555cdc00e80ddfa6a764e5becd4d1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.2b4451a8c10f40b2"

   strings:
      $hex_string = { c00f857801000081feeb03000075078b4424188b70586af053ff1504d64500a80e745b0fb7c650b934e04700e8daebfeff3bc775368b4c24185683c178e8ab06 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
