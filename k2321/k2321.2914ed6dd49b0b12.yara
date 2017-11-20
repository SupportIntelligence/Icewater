
rule k2321_2914ed6dd49b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ed6dd49b0b12"
     cluster="k2321.2914ed6dd49b0b12"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['02865fea0eefdda0978e45fe9c6d1b4b','213e84e49d9ac1c48adf114609aa33c6','fcf027fdf4adba112cb148ab98962f4b']"

   strings:
      $hex_string = { 8a3323929b13c9cd8d64e784b32687b05203d9495a6eb846acd72a95729980bcbdeecbf06beff37d2683c366898402b54211a05107aa157aa534482d0e578ba2 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
