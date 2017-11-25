
rule m3f7_191b3841c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.191b3841c8000b32"
     cluster="m3f7.191b3841c8000b32"
     cluster_size="22"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['20b78b18b19130cd154263550b0be2a6','227ef96f17da81a804dca217d80cae54','ca2c5b91016cc46a358e691d770ddb78']"

   strings:
      $hex_string = { 456c656d656e7442794964282748544d4c3327292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
