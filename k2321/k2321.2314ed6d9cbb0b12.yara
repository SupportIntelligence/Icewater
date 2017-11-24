
rule k2321_2314ed6d9cbb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2314ed6d9cbb0b12"
     cluster="k2321.2314ed6d9cbb0b12"
     cluster_size="7"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy emotet tinba"
     md5_hashes="['0368338a855243be1eeae78cc9e1997d','03e7c7a679d4c7563ce312f677bb5c10','d41e84d29b66d48cf53a05da86b9ee3e']"

   strings:
      $hex_string = { 3b23929d1bce9a1cc24a0d642769b9e11ab15eab54ca6502f2f6ba2fc3afbdcff7990c0e9b25120ad40a4580461da856e895d220b5385c2d8a520ba33582688d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
