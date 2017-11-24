
rule m2321_3b1d9299c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3b1d9299c6220b12"
     cluster="m2321.3b1d9299c6220b12"
     cluster_size="16"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['0596bab8a14892b48953d0897c1f6222','0d602fad881b02ab8ba4a20500af0138','f9c474bfa7119c02fc6dd24d34f53704']"

   strings:
      $hex_string = { c3e63b1732b552caab5d1a3d654f45fc3581db26cb0ea1a0edb18d6c1325eca5e87343241c62292b1d71aa793efa2c615a661ada027e27f30a4cff776ee5d3be }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
