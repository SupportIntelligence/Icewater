
rule j3e7_7114d6c3c8000130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7114d6c3c8000130"
     cluster="j3e7.7114d6c3c8000130"
     cluster_size="5"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['0664cdf4e883fe57e5fd010ab325c28e','30c99352b776389dbbc2fa74a1a9773b','f7519218846a2b328028258caaa65a68']"

   strings:
      $hex_string = { 01620009636c6173734e616d650005636c6f7365001563757272656e74416374697669747954687265616400066578697374730007666f724e616d6500036765 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
