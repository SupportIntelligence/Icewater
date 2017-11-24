
rule k2321_2914ed6d94bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ed6d94bb0b12"
     cluster="k2321.2914ed6d94bb0b12"
     cluster_size="22"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['01073765fb04d59fb63f0e0e65c3fc45','01b98af6ce0b582459788d9fe6749bdc','bfb3d00be7f3e2037ff6c882295ea742']"

   strings:
      $hex_string = { 37929d13ce9a1cc24a0d642769b9e11ab15eab54ca6502f2f6ba2fc3afbdcff7990c0e9b25120ad40a4580461da856e895d220b5385c2d8a520ba33582688d30 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
