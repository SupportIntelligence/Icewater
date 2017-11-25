
rule o3f1_313894c397d30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f1.313894c397d30912"
     cluster="o3f1.313894c397d30912"
     cluster_size="103"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="triada androidos generickd"
     md5_hashes="['08542b63c95c2a8195355fa06dec09de','0a1c73a768600bd5d53bfb501c3b630c','41e7a5f8f3f42e8601361a13e2dfc0c8']"

   strings:
      $hex_string = { 481c25eea2a43299688a148d46230a2e095119b591f334ae369aa5fa26b93d2ce7fdd2b64f1e9ddd03b1cecfbe47a15ddccdb8c2e638a74aff0012d3658598a8 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
