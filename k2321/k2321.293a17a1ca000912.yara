
rule k2321_293a17a1ca000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.293a17a1ca000912"
     cluster="k2321.293a17a1ca000912"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="selfdel generickd zbot"
     md5_hashes="['0f106c7bd0272c9037583750da9b5a9e','17651bed36fcacc4f377db84a5b4831c','ed412df19630106bdec791772ca7b144']"

   strings:
      $hex_string = { 64c2bdb9eaf6db35de6267cca19c3d7b43d9165e2fd9b2571df1372d6afa92f455bc31b89e70479d7e7821f9f3aee7b023f8fcb79b227712ef75a7cd5a433a7f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
