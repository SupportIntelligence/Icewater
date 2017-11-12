
rule m3e9_6b6f078517636796
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b6f078517636796"
     cluster="m3e9.6b6f078517636796"
     cluster_size="91"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal vjadtre wapomi"
     md5_hashes="['1cb509fece173eb5b7413efdc4e04d4e','2c3cfd922d25cfb97243633babb221ce','940f96f59adf06a38316f1a2474d1b3e']"

   strings:
      $hex_string = { 20fb297127fb6e04eedfabc3d9c68a9bf4c0096ee745a4af6e4604c56ad3013352de75cca29f8e154a7afb6c91cb716e8cd1fd9914bddc1d4927aa58188fff01 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
