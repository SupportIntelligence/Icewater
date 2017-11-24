
rule n3e9_091185b8d9e30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.091185b8d9e30912"
     cluster="n3e9.091185b8d9e30912"
     cluster_size="35"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['06d33c97b313fc22f3a523e4b4978b29','1c85faac8eeca09191b645c95722c1b8','6835ef013bf6b54a9267f2990e914c2b']"

   strings:
      $hex_string = { 87d302d9203196cc46921f4daed151dfaaaf6780ff6f93176942f52da03a05faeae7221ce2ed2cf22b1a275acbc803e87c360de67447bf3ea713b49b60baa1f3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
