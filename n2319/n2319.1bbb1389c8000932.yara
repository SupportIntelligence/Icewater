
rule n2319_1bbb1389c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.1bbb1389c8000932"
     cluster="n2319.1bbb1389c8000932"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer miner script"
     md5_hashes="['753d9cda896e5ce261bfa947448bd876995895c4','074129b9b8767785de34b7a3624b4ccf69bbd872','2ef048f9415533d0d062b0b95c622411d1c78286']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.1bbb1389c8000932"

   strings:
      $hex_string = { 657475726e20436f696e486976652e434f4e4649472e4c49425f55524c2b706174687d292c7761736d42696e6172793a73656c662e5741534d5f42494e415259 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
