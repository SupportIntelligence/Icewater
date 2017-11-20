
rule m231b_6bb10098dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.6bb10098dee30912"
     cluster="m231b.6bb10098dee30912"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit script html"
     md5_hashes="['060c208fe8fc6bf2c3ecf082cabe5310','2a7a3c9fd04015723cff36c408044340','f6a5763bb03207fe9f892e26e857fe3d']"

   strings:
      $hex_string = { 434c6e6728222648222026204d6964285772697465446174612c692c322929290d0d0a4e6578740d0d0a46696c654f626a2e436c6f73650d0d0a456e64204966 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
