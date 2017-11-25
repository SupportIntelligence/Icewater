
rule j3e7_7094d6c3c8000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7094d6c3c8000110"
     cluster="j3e7.7094d6c3c8000110"
     cluster_size="13"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos revo"
     md5_hashes="['23719ec7492b5c411220c2fb95bda7d5','28d38e08cc7a4ff561cbfc9b2ecc73b0','e2f394cb0277b30c847ed8170e5f2f15']"

   strings:
      $hex_string = { 0001620009636c6173734e616d650005636c6f7365001563757272656e74416374697669747954687265616400066578697374730007666f724e616d65000367 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
