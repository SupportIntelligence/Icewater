
rule j3e7_7994d6e3c8000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7994d6e3c8000110"
     cluster="j3e7.7994d6e3c8000110"
     cluster_size="6"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos revo"
     md5_hashes="['0b0bd2d23a8e1ca4da83410da3ec0036','7f2c3154ca08b4d6e5a0043c8dbc19eb','cbed4d7d8d4e13524841afbc73bbedbf']"

   strings:
      $hex_string = { 01620009636c6173734e616d650005636c6f7365001563757272656e74416374697669747954687265616400066578697374730007666f724e616d6500036765 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
