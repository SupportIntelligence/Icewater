
rule o3e7_0bb11ee9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.0bb11ee9c8800b32"
     cluster="o3e7.0bb11ee9c8800b32"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonstr dlboost malicious"
     md5_hashes="['3bccf748af19b3cdb6b8b0fc871c13c0','620d49130c1917f345eb83ba583b8c76','c6d443a5196827ed174f5a791677ad49']"

   strings:
      $hex_string = { 3bab2461493f7d4eafda595430e21ff771aa9835b2ebcf7ac206ce1decee5dfd9ea89b843aed457e4408fe325ed081df44946cad86cd4ac01ba00015bd395b63 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
