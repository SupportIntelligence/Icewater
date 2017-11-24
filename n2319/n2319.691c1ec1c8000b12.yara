
rule n2319_691c1ec1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.691c1ec1c8000b12"
     cluster="n2319.691c1ec1c8000b12"
     cluster_size="73"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['029363fef186ccb98b9e2a986d50cd71','04655cab0cbd6bfd7ac50c01b1c74914','441d4ea79f7eaa01accb9057ed8d7bc3']"

   strings:
      $hex_string = { 312f762d6373732f3336383935343431352d6c69676874626f785f62756e646c652e637373277d2c2027646973706c61794d6f646546756c6c2729293b0a5f57 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
