
rule m3f0_291f10e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f0.291f10e9c8800b12"
     cluster="m3f0.291f10e9c8800b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kryptik gepys bcig"
     md5_hashes="['14e5c31c0b42ffd797025054b21db446','72362557d5ab72957c322d0a3086c920','eb2c66c91e410e12385805baccaa0408']"

   strings:
      $hex_string = { bee176b5efbde4c8db480b41952f64b3c74d8d7b460c9eec6362b21969e7bf9710dff8c1cb66eea3eb3d495971650139e3dbca82359f1d1baae62c94b9f9af9b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
