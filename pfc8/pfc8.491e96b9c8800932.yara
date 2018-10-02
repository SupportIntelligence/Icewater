
rule pfc8_491e96b9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=pfc8.491e96b9c8800932"
     cluster="pfc8.491e96b9c8800932"
     cluster_size="749"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smsreg riskware androidos"
     md5_hashes="['823ca2c8e8066f079491fa51deee9c5a7e88d3d3','1bbf3a59fd25d0a491cae81b952ac53282511530','d009ff8aaf1ab5e5613d2f5826d980c676861839']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=pfc8.491e96b9c8800932"

   strings:
      $hex_string = { 4c89a94ab020e79a02a4905763295b328bbe527af59f1d2a23094fa795e0bfb5b3c007223d59747bbc4b49c87113b2b6f112e28cc6f711e4ddce2eda80c25e34 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
