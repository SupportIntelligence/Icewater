
rule k3e9_2914ed6994bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.2914ed6994bb0b12"
     cluster="k3e9.2914ed6994bb0b12"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy emotet tinba"
     md5_hashes="['017dbf3babf2e1d767d1d54c09d3858a','55a9d992db9fdfe401d6b9935d278a20','f8b3d9ce22767c16e8f60585249966aa']"

   strings:
      $hex_string = { cc7736318d8caa4ddce8b195f479baafe542ce06d2285e2e03eeae48e0fb7a867ef35d8509ef1d492f2ae1a6475cda74c53de3d634137acfa4357db4ebbd0ead }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
