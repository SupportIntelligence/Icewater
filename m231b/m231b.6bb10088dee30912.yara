
rule m231b_6bb10088dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.6bb10088dee30912"
     cluster="m231b.6bb10088dee30912"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit script html"
     md5_hashes="['3b6692b9adc3afff821b18d22ca22a96','4d6eadf2ce13240251db7ac239dd2a34','ecb76084bb99e801161a82c0548a5340']"

   strings:
      $hex_string = { 6e672e46696c6553797374656d4f626a65637422290d0d0a44726f7050617468203d2046534f2e4765745370656369616c466f6c646572283229202620225c22 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
