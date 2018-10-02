
rule n26e5_13b54d52ca43c912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26e5.13b54d52ca43c912"
     cluster="n26e5.13b54d52ca43c912"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="pemalform riskware malicious"
     md5_hashes="['b7a61380aca797a730c56234c5014dcfde3ead17','032792c12db361858283fe46ab51b26fa167cc1d','65bf66865c700eb4579bd3a1888332234fa35757']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26e5.13b54d52ca43c912"

   strings:
      $hex_string = { 105f8941040fb644240bf7d889315e1bc025020001e05b8be55dc3cccccccccc558bec83e4f883ec1c8b4508894c241053568bf25783f8ff750e8bcee8bf6dfe }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
