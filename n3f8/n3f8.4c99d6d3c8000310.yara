
rule n3f8_4c99d6d3c8000310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.4c99d6d3c8000310"
     cluster="n3f8.4c99d6d3c8000310"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker gugi androidos"
     md5_hashes="['b78a5876b07cd67f413067c65a175d7103177760','4f5f06da4bf29ec9727486c20102e77183212329','bf2f843af438b34bb26c8fe85b01c4440ae3b940']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.4c99d6d3c8000310"

   strings:
      $hex_string = { 792f4d6573736167654469676573743b00284c6a6176612f73656375726974792f4e6f53756368416c676f726974686d457863657074696f6e3b00194c6a6176 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
