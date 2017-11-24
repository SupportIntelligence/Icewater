
rule k2321_299e6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.299e6a48c0000b12"
     cluster="k2321.299e6a48c0000b12"
     cluster_size="33"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['07a051906ed64d96f6079fa55420b56e','07e07bb2245a11b805660d3039430548','a1405e72a278a7cbcbf30258413e29e8']"

   strings:
      $hex_string = { fd3c669f6293d388832a3ba6b22d793ab942afe7a6ee7aa1c81967b3e1aa940a105d16aff84bfb03a509bb11296a1233865e7d98ae40e3246d5a2fa28e222614 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
