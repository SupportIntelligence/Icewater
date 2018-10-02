
rule n3f8_6d2ade0ccb411132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.6d2ade0ccb411132"
     cluster="n3f8.6d2ade0ccb411132"
     cluster_size="46"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos cloud dldr"
     md5_hashes="['6b41f84255cd0131b550dcc9558bdaa54e60aa43','af3dda07f81e9b072da5f7110578a151985975ba','baf4a3e23af1575d29bf13416d64cc02da107ab5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.6d2ade0ccb411132"

   strings:
      $hex_string = { 4d6574686f643c54543b3e3b002f4c636f6d2f73717561726575702f6f6b687474702f696e7465726e616c2f506c6174666f726d24416e64726f69643b00404c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
