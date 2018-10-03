
rule n26bb_529b33a9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.529b33a9c8800912"
     cluster="n26bb.529b33a9c8800912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious filerepmetagen"
     md5_hashes="['89174ddc35834884e55212462a5d678b8f19bde6','2c259fc04c8cffcca1bc19617afca052304ca5ea','19c541cc6316818e45aa5c2eca51bed88150f278']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.529b33a9c8800912"

   strings:
      $hex_string = { fb09760b80eb1180fb0577d080c30a39f877c9c1e00401d88a1e4684db75d5ebabc350b1ff8a2a4284ed7407408828fec975f25a29d08802c390535081f9ff00 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
