
rule k2321_29146d6d94bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.29146d6d94bb0b12"
     cluster="k2321.29146d6d94bb0b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['07d8187dcd4a9599730616dc59339602','3dcde55d9eb7c89671c41a7e05b68224','90eb249e384184d8a2e85a2917c5f4a9']"

   strings:
      $hex_string = { 37929d13ce9a1cc24a0d642769b9e11ab15eab54ca6502f2f6ba2fc3afbdcff7990c0e9b25120ad40a4580461da856e895d220b5385c2d8a520ba33582688d30 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
