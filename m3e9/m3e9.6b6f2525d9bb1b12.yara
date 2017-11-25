
rule m3e9_6b6f2525d9bb1b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6b6f2525d9bb1b12"
     cluster="m3e9.6b6f2525d9bb1b12"
     cluster_size="20"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod autorun"
     md5_hashes="['024d038b037e3f319ea757f29c7e389c','3f2cf7b014561a0c058235e4e9649256','d8af4c94d6c503c24cba3e0a6f3004d0']"

   strings:
      $hex_string = { 8d78915e20a8c6ec30976e3d8bd3aa42d45ca59026afb3b281b5c82a2ec31ac448a1093b24bed472f67f6135330addb17ca47dbfc16ba286fad52ba9117657e4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
