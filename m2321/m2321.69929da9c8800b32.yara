
rule m2321_69929da9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.69929da9c8800b32"
     cluster="m2321.69929da9c8800b32"
     cluster_size="179"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gator sfyd trickler"
     md5_hashes="['00dc0c1a7496842a92a69d04ac699f30','017cb20dfa7d27624e258c5bc28c9346','221ed04cd1b72caf0fe395d7d73c2952']"

   strings:
      $hex_string = { dc29fbfa8035d4e8d65e509939d824893d01ec6c82d0cf147725222e9686e0f17e8d26d7ab2dbd1a2389e1909b452bf408aeee65b9db30c81d8513734ca7a5b3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
