
rule o3e9_33892949c0000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.33892949c0000916"
     cluster="o3e9.33892949c0000916"
     cluster_size="334"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadsponsor unwanted chipdigita"
     md5_hashes="['00275ebca9bc504ff6f17281f8a07efa','018c1ab01fcae932ad68fd732f954d4e','107a085a17113ef25990d71846140589']"

   strings:
      $hex_string = { 0e2c4bb0e15ab66d1792841b57ee5cba75edde25691265cb22294a6c801061c260c2850d0fa690387105c68d1d3f861cb9b105ca952d5fc09c59f366ce9d3d7f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
