
rule n3e9_53d99ec1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.53d99ec1c4000b12"
     cluster="n3e9.53d99ec1c4000b12"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler agkv"
     md5_hashes="['430f23fec243cdff9b21b77c552d9c52','75512af13b0efd367c23254a565c96fa','d57898894c870f8b94505ff36643c082']"

   strings:
      $hex_string = { 70007500740010004400690076006900730069006f006e0020006200790020007a00650072006f001100520061006e0067006500200063006800650063006b00 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
