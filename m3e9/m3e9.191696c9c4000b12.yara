
rule m3e9_191696c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.191696c9c4000b12"
     cluster="m3e9.191696c9c4000b12"
     cluster_size="90032"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="gator sfyd gain"
     md5_hashes="['0000e207f4b98666a634642b1d0a260e','000283eee8075e955028a0ea5535637b','0011820667bfcd6e2f63ca3e6cddefdc']"

   strings:
      $hex_string = { c8058c6e94b91df6ac1513902ebc0989d24a3e53e9aa3ddf18a92a478381edb88d5f54be4d3bdd807428015c9840d54b7b048ac758caf99e52bf79fc39e1b1a4 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
