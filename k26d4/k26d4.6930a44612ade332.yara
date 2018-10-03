
rule k26d4_6930a44612ade332
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26d4.6930a44612ade332"
     cluster="k26d4.6930a44612ade332"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hacktool patcher riskware"
     md5_hashes="['e4332c40c3db79074ed7dee3b2c74c5f615314c6','85b84ee2988aea5da8af963656edc12d3f823f1d','ca0cf428af0285dbd10524fc50517eb818f55efd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26d4.6930a44612ade332"

   strings:
      $hex_string = { 5d088b7d0c8bd30fb7433c03d88b5b7803da0bff74408b4b188b732003f25333dbad03c2565787f797ac0ac07507803f00740beb073807750347ebedb0015f5e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
