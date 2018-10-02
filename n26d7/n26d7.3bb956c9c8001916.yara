
rule n26d7_3bb956c9c8001916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.3bb956c9c8001916"
     cluster="n26d7.3bb956c9c8001916"
     cluster_size="92"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="trymedia malicious attribute"
     md5_hashes="['0bfd46af09acedc91a53e9ff6cb32310dc165b2b','8d65ffdb70c7294cbfea4aa3624bb3a145a0c77c','0d2dfcbd1c3e9911ab28e83d20290b5b4a8792b4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.3bb956c9c8001916"

   strings:
      $hex_string = { 3bc78945f87513ff15ac90420085c0740950e881adffff59ebcf8bc683e61f6bf628c1f8058b0485005f43008d4430048020fd8b45f88b55fc5f5ec9c36a1468 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
