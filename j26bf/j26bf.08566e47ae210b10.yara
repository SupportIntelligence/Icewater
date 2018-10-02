
rule j26bf_08566e47ae210b10
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.08566e47ae210b10"
     cluster="j26bf.08566e47ae210b10"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dotdo malicious heuristic"
     md5_hashes="['8dd97d096aa2021de183f699719e337d3f945193','50353a09559f451b212ad34c128a14e29daf7efb','bbbc6794614f932ef7f274d085646c506811e6a2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.08566e47ae210b10"

   strings:
      $hex_string = { 6c79436f6e66696775726174696f6e41747472696275746500417373656d626c79436f6d70616e7941747472696275746500417373656d626c7950726f647563 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
