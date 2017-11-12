import "hash"

rule k3e9_1996f3a9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1996f3a9c8000b12"
     cluster="k3e9.1996f3a9c8000b12"
     cluster_size="102"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor razy injector"
     md5_hashes="['07d5382cf934a8a642ba194e02bb032a','08b545d33c290e78a203658521d7cf59','a0aecf44290f50a64665342b66adabd5']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(22528,1024) == "fbd25a257be15565bffdfafe1358c9fa"
}

