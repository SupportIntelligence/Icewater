
rule k26dd_139354f9c9000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26dd.139354f9c9000b16"
     cluster="k26dd.139354f9c9000b16"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hackkms hacktool kmsactivator"
     md5_hashes="['a5376a29a76540d47dfc11ea801f82ecfc269f09','619a511f40e3ea6e11681e7449312e922f8af543','9662e847eac1d682ccb97a27c7ec9cac9599b654']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26dd.139354f9c9000b16"

   strings:
      $hex_string = { 57538d45fc50e8d57e000085c07c2d8b45fc33d28bcbf7f13bc676208bd78945f88b4d0c8b7d088d720a33c0f3a675058b028945f403d3ff4df875e5685f4449 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
