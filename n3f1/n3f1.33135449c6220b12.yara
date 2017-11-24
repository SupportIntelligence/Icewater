
rule n3f1_33135449c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.33135449c6220b12"
     cluster="n3f1.33135449c6220b12"
     cluster_size="4"
     filetype = "Zip archive data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['46b9b75bb124e8e4686d8295e2992479','90dac3e8dca4c3a024f6736ef2242c64','d7d848035be54407fdd7c790e32ba5ae']"

   strings:
      $hex_string = { a2472e1c6aca8f432426994f4a8703da56b0a5697daf0f2fae38d262704997fb8c9f5c5c5840d0eb4d76bfc1393391f159cbeadfd3f9307ec631726692bdbc4c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
