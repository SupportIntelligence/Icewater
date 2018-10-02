
rule n26e5_13b54d52ca47c912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26e5.13b54d52ca47c912"
     cluster="n26e5.13b54d52ca47c912"
     cluster_size="16"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="pemalform riskware malicious"
     md5_hashes="['a27257ba41623106b2a8a22ed7179afb27b88acd','3f6a28a61c1273f121d1f0674e13a51564c5fdc1','91ef567339ae2a676b3e47e43a85d5268dd07752']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26e5.13b54d52ca47c912"

   strings:
      $hex_string = { 105f8941040fb644240bf7d889315e1bc025020001e05b8be55dc3cccccccccc558bec83e4f883ec1c8b4508894c241053568bf25783f8ff750e8bcee8bf6dfe }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
