
rule n26e5_13b54d52ca43d912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26e5.13b54d52ca43d912"
     cluster="n26e5.13b54d52ca43d912"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="pemalform riskware malicious"
     md5_hashes="['8ed596542b058291090f4c005d8b2d1ab7553460','0a351890e0bf86d1b282372c36d9470f917aa66f','6339541a3b7cef570d967ae493a68eebfb44563c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26e5.13b54d52ca43d912"

   strings:
      $hex_string = { 5f8941040fb644240bf7d889315e1bc025020001e05b8be55dc3cccccccccc558bec83e4f883ec1c8b4508894c241053568bf25783f8ff750e8bcee8bf6dfeff }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
