
rule m2321_699294e1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.699294e1c2000b32"
     cluster="m2321.699294e1c2000b32"
     cluster_size="33"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gator sfyd gain"
     md5_hashes="['0834e85a3f2825a7e975627877a3038a','0857480a17c4e78370dc2820652308c4','6d1b1f97561d5215c3f08a37efc1dce7']"

   strings:
      $hex_string = { dc29fbfa8035d4e8d65e509939d824893d01ec6c82d0cf147725222e9686e0f17e8d26d7ab2dbd1a2389e1909b452bf408aeee65b9db30c81d8513734ca7a5b3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
