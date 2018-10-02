
rule n3f8_6818c91d9ac30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.6818c91d9ac30912"
     cluster="n3f8.6818c91d9ac30912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="sandr androidos kasandra"
     md5_hashes="['5fe30d5b01389a4c62ec8558f28ce1cdf1878766','ab4cc8ed67c9954a749915121eaf0a5c7296a062','5225373adf21255cde9f5574720198a7e4914e76']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.6818c91d9ac30912"

   strings:
      $hex_string = { 616765723b001a4c616e64726f69642f6f732f4275696c642456455253494f4e3b00204c616e64726f69642f6f732f4275696c642456455253494f4e5f434f44 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
