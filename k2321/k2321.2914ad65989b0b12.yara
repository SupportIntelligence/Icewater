
rule k2321_2914ad65989b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ad65989b0b12"
     cluster="k2321.2914ad65989b0b12"
     cluster_size="11"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['21e377aabf1a205e886fc8dda0120068','44b12657b9bc9a59cadea9f94746cf5f','dc4451d22365c351d27376d2910a48fb']"

   strings:
      $hex_string = { f4cb24ed0be466136d161dc0baf0d1020310d35c3546df6cffc4b6d9aaf956813e389dec9c9b49d82f3783e86ac995eb8749727389d9e6d5cd5505fa27365720 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
