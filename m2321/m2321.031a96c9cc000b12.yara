
rule m2321_031a96c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.031a96c9cc000b12"
     cluster="m2321.031a96c9cc000b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['300c026e074e11798a75fe28ab150e16','ac47231d76d71a23d801cf3b2efb49fa','e06e3395aedb8d9235b89d65c01f4eb8']"

   strings:
      $hex_string = { 6eb99678d48e9203aed0acc7d8df4b6940236c590779050c2a09bb2f0dfc647574b4b625e1f14e0d2c61ee42da24b0ba6a29578f3ebdddad2d67459793d2171a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
