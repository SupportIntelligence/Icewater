
rule n2319_59995ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.59995ec1c4000b12"
     cluster="n2319.59995ec1c4000b12"
     cluster_size="37"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="likejack faceliker clicker"
     md5_hashes="['1f5188e1c3a9d25225fac4974015c20a37b879e3','cd2e579ad591ff9f556a19a4f8c7ec9b743eddc5','b63434f89c76dd4887c335584c06ae0968fa3714']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.59995ec1c4000b12"

   strings:
      $hex_string = { 22496e76616c6964204a534f4e3a20222b62297d2c7061727365584d4c3a66756e6374696f6e28622c632c64297b612e444f4d5061727365723f28643d6e6577 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
