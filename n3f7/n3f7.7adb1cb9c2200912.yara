
rule n3f7_7adb1cb9c2200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.7adb1cb9c2200912"
     cluster="n3f7.7adb1cb9c2200912"
     cluster_size="23"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['05665af491c338f9e6eb3820e0dc255e','0679f411b8b23c93496bdd438eb2cb1a','a629940cf0b7da0b2ef7d83446dfdf4e']"

   strings:
      $hex_string = { 6369616c466f6c646572283229202620225c2220262044726f7046696c654e616d650d0a49662046534f2e46696c654578697374732844726f7050617468293d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
