
rule p3e9_519ebb49c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=p3e9.519ebb49c8000b12"
     cluster="p3e9.519ebb49c8000b12"
     cluster_size="51"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur cryptor"
     md5_hashes="['1fb35b044681224ca916d7ff785a076a','39af4bc8afe82843f1d18c247f765e7b','b0e2bc5a259c0ad04d610111ef6155e4']"

   strings:
      $hex_string = { 0029292903c3c8cc7ba46d58ffc33c04ffc4591effca6426ffd06a25ffd37230ffe29d73fff1c6aeffecdfd6ffc9eef6ff9fe5f5ff5fceeaff39c3e5ff56cde7 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
