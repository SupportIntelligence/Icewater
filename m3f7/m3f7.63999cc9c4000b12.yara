
rule m3f7_63999cc9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.63999cc9c4000b12"
     cluster="m3f7.63999cc9c4000b12"
     cluster_size="5"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker script"
     md5_hashes="['1525df581e7e5e9e8dcc2a4f7660b1aa','1a6cff4642b6f69e52d0419aeb2c6195','d890a83d146aab94d0da58be30425f67']"

   strings:
      $hex_string = { 2e636f6d2f7265617272616e67653f626c6f6749443d3638373231373038313637313339353634393826776964676574547970653d48544d4c26776964676574 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
