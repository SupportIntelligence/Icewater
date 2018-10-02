
rule n3f8_6da24e97927b1132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.6da24e97927b1132"
     cluster="n3f8.6da24e97927b1132"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos apprisk dldr"
     md5_hashes="['1362ab744031f2c1ada6e522a1b3b9effcc25379','ce742e32dd965e284b2ec40c8b08d31fe9b17305','f86999808441bd7b75e532319154f5f91fc5c277']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.6da24e97927b1132"

   strings:
      $hex_string = { 4d6574686f643c54543b3e3b002f4c636f6d2f73717561726575702f6f6b687474702f696e7465726e616c2f506c6174666f726d24416e64726f69643b00404c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
