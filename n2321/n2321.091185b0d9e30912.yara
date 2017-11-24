
rule n2321_091185b0d9e30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.091185b0d9e30912"
     cluster="n2321.091185b0d9e30912"
     cluster_size="55"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="viking jadtre nimnul"
     md5_hashes="['047c1185cd65a4c04be87f9b49234063','07c8071e60f20fb9bcf6d21929050a5a','34e71938dc4cdf5da695aec017057922']"

   strings:
      $hex_string = { 87d302d9203196cc46921f4daed151dfaaaf6780ff6f93176942f52da03a05faeae7221ce2ed2cf22b1a275acbc803e87c360de67447bf3ea713b49b60baa1f3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
