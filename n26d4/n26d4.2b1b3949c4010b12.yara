
rule n26d4_2b1b3949c4010b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d4.2b1b3949c4010b12"
     cluster="n26d4.2b1b3949c4010b12"
     cluster_size="22"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="cloudatlas malicious neoreklami"
     md5_hashes="['7fd772b44eade332ce5ef8c57619cfcccaee8675','0ebb6775849669732132fb068abba9a96538cf69','86848141c20abff14107017fca4fee8dc33b4305']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d4.2b1b3949c4010b12"

   strings:
      $hex_string = { 0033c9538b5d0c2bd843d1eb3b450c568b75100f47d985db74238bf80fb70750ffd28b55f48d7f0266890683c6028b45fc408945fc593bc375e28b7df089375e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
