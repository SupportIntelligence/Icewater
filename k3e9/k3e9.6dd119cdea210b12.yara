
rule k3e9_6dd119cdea210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6dd119cdea210b12"
     cluster="k3e9.6dd119cdea210b12"
     cluster_size="1580"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="graftor hpdefender malicious"
     md5_hashes="['0018afc9efd01ae7a1ff4babe1b70b1f','00ca18c9d43bd58226e2923bce619900','02860aa64d274e591c9ece5c9a6262a1']"

   strings:
      $hex_string = { 67494341674943416749434167494341674943416749434167494341674943416749434167494341674943416749434167494341674943416749434167494341 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
