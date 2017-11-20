
rule m2321_039ce448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.039ce448c0000b12"
     cluster="m2321.039ce448c0000b12"
     cluster_size="11"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="swisyn bner mofksys"
     md5_hashes="['092d26bf85bace93afff6ab6c2ba67c5','4774393c421c02e48868a256f6eceadf','f95f355c22ae5eda38b3aeb69b9fe36d']"

   strings:
      $hex_string = { 4fb1d0e31b64838c7b79d5f90debdcb4b6956dbbafc6ed5a57cd81d3b292ca7565f46c67899b93493a66ba4aaae94d39d9364e70d473df7633c2982386f05fc9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
