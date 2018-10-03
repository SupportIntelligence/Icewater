
rule n26d7_234d6e5f9ee11b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d7.234d6e5f9ee11b32"
     cluster="n26d7.234d6e5f9ee11b32"
     cluster_size="21"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="zona zvuzona malicious"
     md5_hashes="['b184f6759d7ce033795ac713e7abc9d377dbbdf3','c9033bb072b129f8b24a63b16ea574e104daf2bd','d99afd1242850390d079b003f6ad867ac46bfb4b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d7.234d6e5f9ee11b32"

   strings:
      $hex_string = { 41cca3bc4a42b7f9bf4489ff68fe9dd334e26c44906ed82b32eacdd550595afb552fc1efba67b8c691de125e529fe4bd1811f864be819473713ebb988de7e57c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
