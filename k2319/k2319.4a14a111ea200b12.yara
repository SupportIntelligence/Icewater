
rule k2319_4a14a111ea200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.4a14a111ea200b12"
     cluster="k2319.4a14a111ea200b12"
     cluster_size="3"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker likejack clicker"
     md5_hashes="['00b1eaa0685bd8446d6e0d91b4000c85','47a403c9a696ddb3206746fea02cf1f6','98f9c90e012aad43f11e38322b556b02']"

   strings:
      $hex_string = { 697074273e0a2f2a203c215b43444154415b202a2f0a7661722046425f57503d46425f57507c7c7b7d3b46425f57502e71756575653d7b5f6d6574686f64733a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
