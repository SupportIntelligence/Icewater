
rule j3f8_7194d6a3c8000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.7194d6a3c8000110"
     cluster="j3f8.7194d6a3c8000110"
     cluster_size="23"
     filetype = "Dalvik dex file version 035"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos piom"
     md5_hashes="['001aa0fcb695fa7b25ee0bb266390cb9','00c0f2fac40075e555b39066e8bb7d78','abdcde7934d831b86616936f9d085c72']"

   strings:
      $hex_string = { 01620009636c6173734e616d650005636c6f7365001563757272656e74416374697669747954687265616400066578697374730007666f724e616d6500036765 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
