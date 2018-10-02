
rule m26d4_53e471311aab1132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d4.53e471311aab1132"
     cluster="m26d4.53e471311aab1132"
     cluster_size="25"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="mywebsearch mindspark malicious"
     md5_hashes="['9ae203383cc1d0015fe6962bb936a9ea294ecb68','a9fe1f4a053b67c163e5240d39c9e57e8ee86839','fae76e4f44047abc62590b1b6e749f01cbca1966']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d4.53e471311aab1132"

   strings:
      $hex_string = { 1900115e70536b696e57696e646f775570646174654c697374656e6572575757e8030000480e0000173898e750534555444f5452414e53504152454e545f434c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
