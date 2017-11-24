
rule i3e9_035bb6c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3e9.035bb6c9cc000b12"
     cluster="i3e9.035bb6c9cc000b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['03f46c065f09b31d2734528d13e8f5a5','29d8d7ecd2cb898ccef770928f86825b','b91d3fefebd603fa52178c25c7fae6fc']"

   strings:
      $hex_string = { b796df6fee683d165bf514a7da8db2ca0f9ddea8ddbbf2d4e9cbb9d849bcbdb661e9bdeae45429b6da51ac3e1ebf746743f55aecae1aeb5d4afa42cc2eaf2d8e }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
