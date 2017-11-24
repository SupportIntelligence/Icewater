
rule m2321_2998918dc6220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2998918dc6220b32"
     cluster="m2321.2998918dc6220b32"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['0bd011ea629dbed822b4abe8fab423c7','26799c282bd48bb925d67bb2c2d42f55','d761a23dd1599c0426c97c25234703ff']"

   strings:
      $hex_string = { 991cae83b3137fa149be8ffef2ac68030baa5c75477b59b00c7120d29572decdf4fb275d2e10edb74b4fc89c0aa48eb13aad7c1989c02233a63d521a73db3629 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
