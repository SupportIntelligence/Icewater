
rule n2321_191a299bc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.191a299bc6220b32"
     cluster="n2321.191a299bc6220b32"
     cluster_size="49"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar virtob shyape"
     md5_hashes="['003ffada3c8c8cd3e9a0bea8f0e55bd2','0cd81aee54a79a72337a13c86905be39','5834d520a6dcfedf8f66d2248673702b']"

   strings:
      $hex_string = { f44dbb4c5fdc0dad5384c79f70f1dd9cf7db047d881226f01cd07867e5c5acaad9d777ae606b831b7163a7f964799422a84f452fa911e1deba7fe7612cb913b1 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
