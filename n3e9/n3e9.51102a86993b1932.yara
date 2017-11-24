
rule n3e9_51102a86993b1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.51102a86993b1932"
     cluster="n3e9.51102a86993b1932"
     cluster_size="212"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="getnow livesoftaction unwanted"
     md5_hashes="['01e833960587fe16aebb159e34198b94','0217b6d98153bb2a2c1cee234f915230','100a14e24b6ca0dad87b13ab163cfcf7']"

   strings:
      $hex_string = { 9b4960c17d676920800fef59776803a1e40d9af84d1ec847190e868556578d02f0290bf9c990121ff6eb5aac6590787b97753e8e526392ba4a737041226400c2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
