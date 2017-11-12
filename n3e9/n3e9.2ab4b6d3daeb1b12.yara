
rule n3e9_2ab4b6d3daeb1b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2ab4b6d3daeb1b12"
     cluster="n3e9.2ab4b6d3daeb1b12"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['0d7ada1f8ebe38c186dbd08c6abccb58','b7c6949c6b0fd783b65873263fe79031','c1367af4e9fdcbde281a9a903e26540e']"

   strings:
      $hex_string = { 488b4424142b44240c89434c8bc3e8ea68ffff83c4445f5e5bc38d40005356575583c4f88914248be88b85d001000085c074418b78084f85ff7c3947c7442404 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
