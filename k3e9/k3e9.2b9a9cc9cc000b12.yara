
rule k3e9_2b9a9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b9a9cc9cc000b12"
     cluster="k3e9.2b9a9cc9cc000b12"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="rincux ddos stormattack"
     md5_hashes="['0101495f3f70d48ce850e89f2da43bf9','18675fa08fdd2de2c01f3336535323f9','dca5e16f9f9b3fb9fb5ffae50a6b7f20']"

   strings:
      $hex_string = { ae1aef6194e4a5b79c556a333bf82d9a99df53d90f66e6a90a2c97c72e220e74f05f2fb4e9153f710b2096bebaaa4c12f8ac4f03a6ed16254ec8b3283e27cda2 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
