
rule k26bb_65d852ef9e630912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.65d852ef9e630912"
     cluster="k26bb.65d852ef9e630912"
     cluster_size="398"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="adwaresail ejtxwd heuristic"
     md5_hashes="['af227198d42a5494e85754c67c2fddd4656d86ef','2e7cdd2f6fec6ad91e21cf1c36eb3f315ef6f7ef','df4fb8a6094938fbb83758b97f929d0d70669afa']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.65d852ef9e630912"

   strings:
      $hex_string = { 685ca5400050ff15ec80400083c70aeb3583c00a6858a5400050e8f9fcffff8be885ed741d8d0c3e8d0419eb068a11881048493bcd77f62bee458bc58b6c2418 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
