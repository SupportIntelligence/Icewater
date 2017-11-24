
rule m2321_291d9699c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.291d9699c2200b12"
     cluster="m2321.291d9699c2200b12"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['020328b6a21f14a646825eda376c3c63','1a9e785842b487e77d4eccb873c5b225','c906ddaf3d5b66d4dc7ac5f55e8f9be3']"

   strings:
      $hex_string = { 866e4882614ccd26237eece87141a9ba095ae0f084174dced0aac6478f05fc66204ef10d68972d35024659fae4286da25607ad3bc3ab1d2b5f577d9955144b29 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
