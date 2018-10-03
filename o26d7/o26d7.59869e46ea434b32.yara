
rule o26d7_59869e46ea434b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d7.59869e46ea434b32"
     cluster="o26d7.59869e46ea434b32"
     cluster_size="249"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="safebytes malicious dllkit"
     md5_hashes="['36c94792c2e70a4e046aaa05038ed745adeb2fbe','97599f40168af09732e4a6c2ba89aa52c3b302d5','98480e6210070042de9fd6e0c6131221aa9d93cf']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d7.59869e46ea434b32"

   strings:
      $hex_string = { c3e9e495f4ffebd85f5e5b8be55dc2040000d85332b02077684bb10ae3e79b91ecd3175f39d0aa52154593a55b292f03aa7b05278ce85a7c664e9b81447d05d5 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
