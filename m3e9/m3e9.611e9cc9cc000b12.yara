
rule m3e9_611e9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611e9cc9cc000b12"
     cluster="m3e9.611e9cc9cc000b12"
     cluster_size="2137"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack backdoor"
     md5_hashes="['000a2d9a608cbfc87190c682262d0e4f','000b603de8fc17893b3d13a449f16ef9','059747dd099f25b150756c8b289eaf80']"

   strings:
      $hex_string = { 46e0b621276297a307e47725e86658a7c8e83829a96a19ab89ecf92d6a6edaaf4af0ba312b729bb30bf47b35ec765cb7ccf83c39ad7a1dbb8dfcfd3d6e7edebf }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
