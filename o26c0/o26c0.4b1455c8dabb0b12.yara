
rule o26c0_4b1455c8dabb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26c0.4b1455c8dabb0b12"
     cluster="o26c0.4b1455c8dabb0b12"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor malicious gjjv"
     md5_hashes="['7d20ca94ae516b90a838ddf48c60f7a26ef9e746','dfddf3c5bf5f901a9edad4fa5a44c79ebe62f2d5','3818eacdcab5b498b46bd66ab6d00a244c6924e9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26c0.4b1455c8dabb0b12"

   strings:
      $hex_string = { 1c0620d3e704fd8653ff34984672354a14b3759de8859c05d0502bba5d00f38eb26c41e97761088384cef4ebbda5a2e669539f3a3f403700ac0e45ea8192f97e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
