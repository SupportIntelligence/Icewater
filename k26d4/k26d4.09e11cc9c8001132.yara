
rule k26d4_09e11cc9c8001132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26d4.09e11cc9c8001132"
     cluster="k26d4.09e11cc9c8001132"
     cluster_size="34"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="goopdate riskware alteredsoftware"
     md5_hashes="['a80e50498ba94241baf0d56a059eb9128fc48e67','660f732b5e3f5ab0fa224e6fd1bf579008026b3f','2806a0e4f67a18d026cbc0a3bbf1e38338969334']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26d4.09e11cc9c8001132"

   strings:
      $hex_string = { 49ffa2b39dfffcf3feffe4fadfff7cda65ff60d144ff69d44fff53ce35ff3fcd1cff337e13e523460a139fbc8c008fb1799451c132ff58d23cff76d85eff75d7 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
