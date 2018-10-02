
rule j26d4_14a26babcae2f16a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26d4.14a26babcae2f16a"
     cluster="j26d4.14a26babcae2f16a"
     cluster_size="43"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious proxy"
     md5_hashes="['37c7af1bcf947273829c046021b86ad6b6f1cc96','a65af89f3b0e3df215d9d22c7b5834a38c1b113e','59cb844345cba84487efa2a81ad39461d4d0edd7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26d4.14a26babcae2f16a"

   strings:
      $hex_string = { 4b504646ff374e4e81eb882301005b5883fb000f85fd0900000f84240a0000d3fa589b1d9420b981b42cbe81f22e9381b23cbfcbd20ad747f356c66dab6b2212 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
