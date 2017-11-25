
rule m2377_219b2808dabb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.219b2808dabb0932"
     cluster="m2377.219b2808dabb0932"
     cluster_size="6"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit script html"
     md5_hashes="['44b727b77b56d9783ec830821a6047f5','90fa8e8d8bee1e031021200ca0636a92','f8013e982fee9184fd6e38b9857668c4']"

   strings:
      $hex_string = { 6e672e46696c6553797374656d4f626a65637422290d0a44726f7050617468203d2046534f2e4765745370656369616c466f6c64657228322920262022222026 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
