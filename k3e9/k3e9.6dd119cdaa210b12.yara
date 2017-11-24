
rule k3e9_6dd119cdaa210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6dd119cdaa210b12"
     cluster="k3e9.6dd119cdaa210b12"
     cluster_size="965"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious attribute high"
     md5_hashes="['00ebb0f8683b62f5dce415a0f32e7998','01508eff241999823e025e320e83f5af','0409ab77ef6a02a7716df16bbeeca6dc']"

   strings:
      $hex_string = { 49434167494341674943416749434167494341674943416749434167494341674943416749434167494341674943416749434167494341674943416749434167 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
