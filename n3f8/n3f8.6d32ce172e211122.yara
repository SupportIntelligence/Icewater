
rule n3f8_6d32ce172e211122
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.6d32ce172e211122"
     cluster="n3f8.6d32ce172e211122"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos cloud dldr"
     md5_hashes="['b0f957e7643d915eb556b606dd982389200bca36','357d5baed2d235fd748e100565cf4be7b8c22497','bae042df72307c2cd0d956ff89f11b51ec2546f4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.6d32ce172e211122"

   strings:
      $hex_string = { 4d6574686f643c54543b3e3b002f4c636f6d2f73717561726575702f6f6b687474702f696e7465726e616c2f506c6174666f726d24416e64726f69643b00404c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
