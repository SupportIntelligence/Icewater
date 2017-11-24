
rule k3e9_0119bce9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0119bce9c8800b12"
     cluster="k3e9.0119bce9c8800b12"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="mydoom email banker"
     md5_hashes="['15d2403edac346778367905ad55e56ce','22b450bc623f633fe86bdff117249c5f','9e97a445a24a656523b116d56967770b']"

   strings:
      $hex_string = { a75b269b8552d9874254a8d25f6abee48dd61e202a65ed0129e7f8e2dafdc3a30948132d31155646a68035c6e5cdf100511f3d12037090954a4dd53a50f68ee1 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
