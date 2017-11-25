
rule k3e9_0cb94a52dc62f112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0cb94a52dc62f112"
     cluster="k3e9.0cb94a52dc62f112"
     cluster_size="22530"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="unruy cosmu cycler"
     md5_hashes="['0000ccdd4db5339c9ea00dbf30903e63','000349ce6bf22d1f3ab9894e03c1755c','0068eb20f59b65afd91fdc51418c62ee']"

   strings:
      $hex_string = { 59e45d9246a3d54fd9c515a46b51ddaf48fb5810eef2febc4bf79d73603ee5a0cca176a6f8918cf59b3729b52e7757bddf74ac8a0d1d56de5c9500ec6945c8ed }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
