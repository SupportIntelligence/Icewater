
rule m2377_711d8e29e4016b36
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.711d8e29e4016b36"
     cluster="m2377.711d8e29e4016b36"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['258520ab71f61a2ddc8e9fec5ac20f52','414b6926f1ec3e04e4a73a2fd99f255a','954fda18362ecbd380800992ae61c669']"

   strings:
      $hex_string = { 6e672e46696c6553797374656d4f626a65637422290d0a44726f7050617468203d2046534f2e4765745370656369616c466f6c646572283229202620225c2220 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
