
rule k2321_2114ed69949b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2114ed69949b0b12"
     cluster="k2321.2114ed69949b0b12"
     cluster_size="16"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt emotet tinba"
     md5_hashes="['05b912b75e2debab38ac6f270d5146e6','27a537b3924742f8e2a5e03e0f2f048d','edbffde4ce5a2d6bacb30d3f47a3e67f']"

   strings:
      $hex_string = { 9dafbd76fce85187dd66b1588e1d3d06e67df0fe7bed7c5ec962715928d9852456222c21448b454aa9c45fad421409f6d7614f8c30680d2ad26bb004ec417cca }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
