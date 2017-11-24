
rule i3e9_0253b6c9cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3e9.0253b6c9cc000b16"
     cluster="i3e9.0253b6c9cc000b16"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['3d0b47cefde1c2a3c80c04256faa57f9','7b739db232e01d3a165d977178318591','9cc4020316e24112c1dcce79ee2176fd']"

   strings:
      $hex_string = { 6aa9104e8e8c3f3d327af089ace370b0fdab0b176b73d5fab942989c1819df8c57778c975e185b2cd52e4f152b8ba5914bb1e7621a7b26ceee64e9721a383a3c }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
