
rule k403_139294f9c9000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k403.139294f9c9000916"
     cluster="k403.139294f9c9000916"
     cluster_size="1494"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hackkms risktool hacktool"
     md5_hashes="['00049401d02142c2d7b296202c4d86f4','006c8ac84a35795a4faf13cb5a1660b5','024aabc2b6b78e71e73ace280a0b69ff']"

   strings:
      $hex_string = { 57538d45fc50e8d57e000085c07c2d8b45fc33d28bcbf7f13bc676208bd78945f88b4d0c8b7d088d720a33c0f3a675058b028945f403d3ff4df875e5685f4449 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
