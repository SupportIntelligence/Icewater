
rule m2377_7939400adfa30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.7939400adfa30912"
     cluster="m2377.7939400adfa30912"
     cluster_size="7"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['03173d0a353275120abb7cefa62675ed','114682f549c525ec6eab124fd2f40d63','f7992ede3bda9a8e8a554c69bb992bea']"

   strings:
      $hex_string = { 6e672e46696c6553797374656d4f626a65637422290d0a44726f7050617468203d2046534f2e4765745370656369616c466f6c646572283229202620225c2220 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
