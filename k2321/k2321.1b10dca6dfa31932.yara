
rule k2321_1b10dca6dfa31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.1b10dca6dfa31932"
     cluster="k2321.1b10dca6dfa31932"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hupigon backdoor razy"
     md5_hashes="['17d07268fb482ce49d4cb3bfd4d9f3db','1e253bb50826103f796fbd5fcf7d3ded','b3d39989252cd343d1589c0168b68b5a']"

   strings:
      $hex_string = { 48b330203a92a55d161f98c478889475fadef2628eacdd538974522134615a09e5d72d6914d90e18522be8d8a6a4725c3e32a3a095be8ec6e136bd9a83514a6f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
