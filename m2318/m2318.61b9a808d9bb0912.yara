
rule m2318_61b9a808d9bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.61b9a808d9bb0912"
     cluster="m2318.61b9a808d9bb0912"
     cluster_size="29"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['08488b07054ca02b22e5e08b25046779','149c9af96501cb6b372b8a346d3269eb','992734776627a46e91d4e9ee4751cae1']"

   strings:
      $hex_string = { 696e672e46696c6553797374656d4f626a65637422290d0a44726f7050617468203d2046534f2e4765745370656369616c466f6c646572283229202620225c22 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
