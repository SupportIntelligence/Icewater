
rule j3f8_7094d6c3c8000310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7094d6c3c8000310"
     cluster="j3f8.7094d6c3c8000310"
     cluster_size="10"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['01680b1592697e6f9544ef75944ef8fe','03e9286d07069f677ee2642282118a10','ce2988fd06ea2bfc88a769b367980137']"

   strings:
      $hex_string = { 0001620009636c6173734e616d650005636c6f7365001563757272656e74416374697669747954687265616400066578697374730007666f724e616d65000367 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
