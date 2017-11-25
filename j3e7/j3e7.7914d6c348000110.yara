
rule j3e7_7914d6c348000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7914d6c348000110"
     cluster="j3e7.7914d6c348000110"
     cluster_size="7"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos shedun lockscreen"
     md5_hashes="['19c681a926bf0d72a8fd08475330a785','80a6c2ac3b4bde7d82e97adef952eb4d','d6d346d5642781adf351bf3a310d7ccd']"

   strings:
      $hex_string = { 0001620009636c6173734e616d650005636c6f7365001563757272656e74416374697669747954687265616400066578697374730007666f724e616d65000367 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
