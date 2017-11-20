
rule k2321_291ced6c9c9b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.291ced6c9c9b0b12"
     cluster="k2321.291ced6c9c9b0b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['2c6645f014ccebb3f058dea1a7ee6034','524fd72692c9d1e678264a25b2787895','caeebf20d32d881d43ea1913ea940245']"

   strings:
      $hex_string = { 6591ce02522e50379422c7c17911d514f5c58aba42047d596d3e81a47286b86abaa861a6d03c837f7e32078dd88bbd19d31324dd228260a04c2a454727e0b4cd }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
