
rule m3e9_6b2f2525d9eb1b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b2f2525d9eb1b12"
     cluster="m3e9.6b2f2525d9eb1b12"
     cluster_size="465"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod malicious"
     md5_hashes="['0063e68a16c8911779fbbf3637787354','0236ebbe706b298107a854ee871d30d4','2c39148eeb0e92984f8fd6f58c8eae62']"

   strings:
      $hex_string = { 8d78915e20a8c6ec30976e3d8bd3aa42d45ca59026afb3b281b5c82a2ec31ac448a1093b24bed472f67f6135330addb17ca47dbfc16ba286fad52ba9117657e4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
