
rule n26d5_2d1596ab651b4bba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.2d1596ab651b4bba"
     cluster="n26d5.2d1596ab651b4bba"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['f58d6b47d0466519c753f0d15dd43b00c93806c0','5240a74601fae177564c47b75448f74e1279b5c5','27fdfd236aa2c9dcd5a05575db1dc1bfe8184707']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.2d1596ab651b4bba"

   strings:
      $hex_string = { 6bf1ce85491a510f15f739b5586779b9412b4a2869cdfd877652d010aa002d1c326f95970103a7e893dd35d7377e4819777268a31f54dfc5a67bdb6d7aa95c1b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
