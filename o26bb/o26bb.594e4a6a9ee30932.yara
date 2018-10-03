
rule o26bb_594e4a6a9ee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.594e4a6a9ee30932"
     cluster="o26bb.594e4a6a9ee30932"
     cluster_size="282"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious axhos"
     md5_hashes="['7fb3d535ee133345aa1aa1dcf16ad2cd6792333f','ca219635d744cfb858daf4e782f56f2ae4bb91e9','ce9896145f7a0492258899aa99b4d7642b4fbadc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.594e4a6a9ee30932"

   strings:
      $hex_string = { 55544638537472696e67e9fd0200fc2340000a0d52617742797465537472696e67ffff020000142440001408504c6f6e67496e749c1040000200282440001405 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
