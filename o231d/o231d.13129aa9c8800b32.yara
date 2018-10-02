
rule o231d_13129aa9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o231d.13129aa9c8800b32"
     cluster="o231d.13129aa9c8800b32"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="smspay riskware androidos"
     md5_hashes="['cabaf7172771b447ef2a24b6fc7ff34b64fd71e9','0a6b34df4556c7650ea9c666d9cc2efdb870f1bc','1ff7e47e21424a84279806b3381b15f6493122d2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o231d.13129aa9c8800b32"

   strings:
      $hex_string = { 6633bb38c6151ef29e1fc42b230f284c45ead086be8c6412f358c5014ef184f7442cabd64942364a528b8ef46334b359cb412e719bd7fc245a90ba2203b92947 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
