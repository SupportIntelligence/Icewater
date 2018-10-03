
rule n26d7_5d9b96b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.5d9b96b9c8800b32"
     cluster="n26d7.5d9b96b9c8800b32"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="xcnfe malicious genx"
     md5_hashes="['64d23a034a4fd0e17af0ba5a1709277d9a7a43fb','c417f858b5df7f2239bcc060961bb0c497073f36','da3b391c9b1ab2cd171309fd37a162f70034cdaf']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.5d9b96b9c8800b32"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
