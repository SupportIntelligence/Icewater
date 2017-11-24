
rule k2321_2114ed699cbb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2114ed699cbb0b12"
     cluster="k2321.2114ed699cbb0b12"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="emotet tinba vbkrypt"
     md5_hashes="['3ec0f6a82c90a3af94521b07a3850049','b98a1b68e62f29cf95883ee22e83dbe7','eeb52ccc4787b0168a9733377ee61c06']"

   strings:
      $hex_string = { 3b23929d1bce9a1cc24a0d642769b9e11ab15eab54ca6502f2f6ba2fc3afbdcff7990c0e9b25120ad40a4580461da856e895d220b5385c2d8a520ba33582688d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
