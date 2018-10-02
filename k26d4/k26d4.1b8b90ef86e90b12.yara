
rule k26d4_1b8b90ef86e90b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26d4.1b8b90ef86e90b12"
     cluster="k26d4.1b8b90ef86e90b12"
     cluster_size="269"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="symmi genpua olympus"
     md5_hashes="['4bbbb201d0a9735c426db6ada18ccd02e52d94f6','31ddf2f4e1a92d0b0a5e4d6fd7e4bb446153c455','3d19bd5009fb411efe073e869ed3b62c8fd4dfd1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26d4.1b8b90ef86e90b12"

   strings:
      $hex_string = { d5a6cfff491f78c2d340a3149bc516abb3ef3d41e08ce980c947ba93a841aa17e67f2ba116b612426b5527398df770e07c4230c93ce3ff96528ae7428edef99d }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
