
rule m231b_63b12088dee30916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.63b12088dee30916"
     cluster="m231b.63b12088dee30916"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit script html"
     md5_hashes="['0bf444951d96a5e5a65dd03d3dc34ee0','2b0a0ebb856e9e59256140d51d442379','9d63cf1f2aaa1b0721e837acceffc7cc']"

   strings:
      $hex_string = { 696e672e46696c6553797374656d4f626a65637422290d0d0a44726f7050617468203d2046534f2e4765745370656369616c466f6c646572283229202620225c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
