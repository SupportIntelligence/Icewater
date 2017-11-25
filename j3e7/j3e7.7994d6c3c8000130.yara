
rule j3e7_7994d6c3c8000130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7994d6c3c8000130"
     cluster="j3e7.7994d6c3c8000130"
     cluster_size="647"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos risktool"
     md5_hashes="['002cf916c93c374a183bcdbbe8e61e87','0070d7efb78323518f6e12372bce9d7c','06bfc1d8a8883368d46e5e37d826b17f']"

   strings:
      $hex_string = { 0001620009636c6173734e616d650005636c6f7365001563757272656e74416374697669747954687265616400066578697374730007666f724e616d65000367 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
