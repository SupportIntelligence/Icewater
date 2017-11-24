
rule k2321_2914ed6d9cbb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ed6d9cbb0b12"
     cluster="k2321.2914ed6d9cbb0b12"
     cluster_size="66"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy emotet tinba"
     md5_hashes="['00e00ca787075d2e7ced2200536948af','0e3debd8974b8dfe5661a6d605831e90','5d2fbd3370b67d73870ae8dae1ed52fb']"

   strings:
      $hex_string = { 3b23929d1bce9a1cc24a0d642769b9e11ab15eab54ca6502f2f6ba2fc3afbdcff7990c0e9b25120ad40a4580461da856e895d220b5385c2d8a520ba33582688d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
