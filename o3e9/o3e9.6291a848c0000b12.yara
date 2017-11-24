
rule o3e9_6291a848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.6291a848c0000b12"
     cluster="o3e9.6291a848c0000b12"
     cluster_size="769"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="driverupdate fakedriverupdate sality"
     md5_hashes="['00738c68914cf0b7ae83d52cea2beda9','00e5996a0bd64283e5e9d86ad0ff9ee5','03f5ae3eccb9a74252c42d8467d5d1ae']"

   strings:
      $hex_string = { 52902e6087efc57dd75856c41eed425e092c8c3afb0b723927d1b5ae363702a00d79018f6851c61fc7f910bae10699d0410445de0f4e4bc349e5b088835bc034 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
