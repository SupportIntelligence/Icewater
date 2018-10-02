
rule n2319_2b1492edee200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.2b1492edee200912"
     cluster="n2319.2b1492edee200912"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fakejquery script classic"
     md5_hashes="['3f01df3e99bd2a9f2d5d7b2e5a45915e47e6cf04','8d27132629144dcc1ea030378e2cde03189c9a0a','98522f992d8308270eaa93c82793bd34a0210e9c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.2b1492edee200912"

   strings:
      $hex_string = { 6774687c7c6d2e6572726f722822496e76616c696420584d4c3a20222b62292c637d3b7661722079622c7a622c41623d2f232e2a242f2c42623d2f285b3f265d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
