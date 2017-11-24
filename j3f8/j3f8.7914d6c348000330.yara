
rule j3f8_7914d6c348000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7914d6c348000330"
     cluster="j3f8.7914d6c348000330"
     cluster_size="4"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['267c3e3d17afe1ed49d964dedbdfe482','405d8e5506f4773bc89f43026e37e10f','e3f11d67cadcaa40cce822fc33a98135']"

   strings:
      $hex_string = { 01620009636c6173734e616d650005636c6f7365001563757272656e74416374697669747954687265616400066578697374730007666f724e616d6500036765 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
