
rule m2321_0394ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.0394ea48c0000b12"
     cluster="m2321.0394ea48c0000b12"
     cluster_size="20"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="swisyn mofksys bner"
     md5_hashes="['0563285a8df1c6c43834cba3f0442489','06580fdef6d46e193111045a7ef23ed9','b507abe61ed1f075b7ad98bab8eed695']"

   strings:
      $hex_string = { 4fb1d0e31b64838c7b79d5f90debdcb4b6956dbbafc6ed5a57cd81d3b292ca7565f46c67899b93493a66ba4aaae94d39d9364e70d473df7633c2982386f05fc9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
