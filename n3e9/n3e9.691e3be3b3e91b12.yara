
rule n3e9_691e3be3b3e91b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.691e3be3b3e91b12"
     cluster="n3e9.691e3be3b3e91b12"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious ramnit attribute"
     md5_hashes="['4f58e2bc6589035f34140e747fb05edd','6a343bf3f47fa15cb08853cc487d49f2','e1cf4ab4915714577b5d2173970d8d0c']"

   strings:
      $hex_string = { f8037cf3eb668bc6996a1f5923d103c2c1f80581e61f00008079054e83cee0468365080033d22bce42d3e28d4c85e08b318d3c163bfe72043bfa7307c7450801 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
