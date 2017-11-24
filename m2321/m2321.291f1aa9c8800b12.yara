
rule m2321_291f1aa9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.291f1aa9c8800b12"
     cluster="m2321.291f1aa9c8800b12"
     cluster_size="15"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gepys kryptik bcig"
     md5_hashes="['05e8b44b5fd61b299a80ecbcfa566a9c','1b89d440f08b857143f2fee97c5f3481','ed8edf396277070f3d89f99d0cbc42c3']"

   strings:
      $hex_string = { bee176b5efbde4c8db480b41952f64b3c74d8d7b460c9eec6362b21969e7bf9710dff8c1cb66eea3eb3d495971650139e3dbca82359f1d1baae62c94b9f9af9b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
