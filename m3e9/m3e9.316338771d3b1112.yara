
rule m3e9_316338771d3b1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316338771d3b1112"
     cluster="m3e9.316338771d3b1112"
     cluster_size="520"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod autorun"
     md5_hashes="['00a83ef4a4b315829ffb1989231f5d13','0177015e286b35e28177a4bccf672945','195a519eaf7666dcab0a0e1b98a0b33a']"

   strings:
      $hex_string = { 8d78915e20a8c6ec30976e3d8bd3aa42d45ca59026afb3b281b5c82a2ec31ac448a1093b24bed472f67f6135330addb17ca47dbfc16ba286fad52ba9117657e4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
