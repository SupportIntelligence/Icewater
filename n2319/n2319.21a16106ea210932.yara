
rule n2319_21a16106ea210932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.21a16106ea210932"
     cluster="n2319.21a16106ea210932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer miner script"
     md5_hashes="['1abc19019eb74649a4d4efce392aea37ebef9c5a','0a47dc94621a9a17e69b021343a3abbda82ab968','dbde97072ba8380cab719e44c894c8caed126fa8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.21a16106ea210932"

   strings:
      $hex_string = { 776865656c44656c746158292c226178697322696e20752626752e617869733d3d3d752e484f52495a4f4e54414c5f41584953262628733d2d312a6f2c6f3d30 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
