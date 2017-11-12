import "hash"

rule k3e9_2b19f3a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2b19f3a9c8000b12"
     cluster="k3e9.2b19f3a9c8000b12"
     cluster_size="67"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy backdoor injector"
     md5_hashes="['086b2ee626ff96766087457c31fbeed9','0e2306f167b3f2750eb653782133fe90','8d1431c40a9e7b1d140d3f5ac85f6cd1']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(22528,1024) == "fbd25a257be15565bffdfafe1358c9fa"
}

