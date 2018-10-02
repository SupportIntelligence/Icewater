
rule m26bb_61183ac1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.61183ac1cc000b12"
     cluster="m26bb.61183ac1cc000b12"
     cluster_size="65"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="allaple rahack malicious"
     md5_hashes="['82f1734b2f1cf9f914c98e7b1dff4d99fa2529e3','8a66c06bde641fdc6ecf53bc16245b4b8367cfbf','ee130d3d77156cb6b9bdc2378bbbef3432c62cd0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.61183ac1cc000b12"

   strings:
      $hex_string = { 0f8c000c83a27e2cec3663df144b0df4d0a7ba4cc087b73275fe4f29a15f88fa71fc02e09c2fd1446f68b6bdef45ad82671a7fe52e1cd8621965ce20c8bc21c3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
