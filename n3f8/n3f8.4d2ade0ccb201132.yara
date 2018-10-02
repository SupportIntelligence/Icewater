
rule n3f8_4d2ade0ccb201132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.4d2ade0ccb201132"
     cluster="n3f8.4d2ade0ccb201132"
     cluster_size="44"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos dldr entxvm"
     md5_hashes="['66c8becd8489911a6091b064e7fe7a1e44383035','cbe131cac07ae34e55dda85ab55adc270ead28cc','2ca98c1c8b3b7f7913964344d157a1634ca2efa1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.4d2ade0ccb201132"

   strings:
      $hex_string = { 4d6574686f643c54543b3e3b002f4c636f6d2f73717561726575702f6f6b687474702f696e7465726e616c2f506c6174666f726d24416e64726f69643b00404c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
