
rule n2321_293185b8dde30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.293185b8dde30912"
     cluster="n2321.293185b8dde30912"
     cluster_size="7"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre otwycal fujacks"
     md5_hashes="['1e13252d320f2d88a09860685cf83bb4','5bac9294c32b326f92af388d93008758','fa5a4b822a2bc4400273f03083447efc']"

   strings:
      $hex_string = { e173bdfea36c5df6904902ee8142be8906033ee6df9b1ea1c500e4f3940f3ccf4f7f5993af15ea1dd7fb537ed2b539103a2fd4d1ec650ba6868a6740bc72324c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
