
rule nfc8_5acacec5ea211112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.5acacec5ea211112"
     cluster="nfc8.5acacec5ea211112"
     cluster_size="197"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos fakeinst hiddenads"
     md5_hashes="['1c75bd49beb22a5d1368fd66b217f98aa0f982f7','0bb6f3c65392773bbc499f034085372f70a5b4c0','f520c309dc66d87c95adf8a88627e18156835514']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.5acacec5ea211112"

   strings:
      $hex_string = { 0e002304340430043b04380442044c042000370430043f0440043e04410400000c00530065006100720063006800200071007500650072007900000010001f04 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
