
rule m2321_699297a9ca000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.699297a9ca000b32"
     cluster="m2321.699297a9ca000b32"
     cluster_size="158"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gator sfyd gain"
     md5_hashes="['00364e963073c7be797968dd5ae98dd2','032edb9f70f503298e60c0eed2e12819','1f1f090308ac14a6c74f8b77f49bd6f6']"

   strings:
      $hex_string = { dc29fbfa8035d4e8d65e509939d824893d01ec6c82d0cf147725222e9686e0f17e8d26d7ab2dbd1a2389e1909b452bf408aeee65b9db30c81d8513734ca7a5b3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
