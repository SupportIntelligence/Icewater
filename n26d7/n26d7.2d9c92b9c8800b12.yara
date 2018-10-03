
rule n26d7_2d9c92b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.2d9c92b9c8800b12"
     cluster="n26d7.2d9c92b9c8800b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="xcnfe malicious genx"
     md5_hashes="['51597917fcf6135461949a6539fd1b5c534881eb','b0f6dbf6fa47bd0786edb03b8bb039e24e88155a','a95be7d1818b2abc8490281cb1ef171532a4058f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.2d9c92b9c8800b12"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
