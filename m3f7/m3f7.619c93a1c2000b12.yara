
rule m3f7_619c93a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.619c93a1c2000b12"
     cluster="m3f7.619c93a1c2000b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['22526f3eea5c493de8c83e54da60e65b','26917c206c74a6d545ae690956ba1ace','faca97ee51cc1161ac8fe5156dc51ba1']"

   strings:
      $hex_string = { 4d6963726f736f66742e416c706861284f7061636974793d3029262333393b3b20206d617267696e2d6c6566743a202d353070783b207a2d696e6465783a2031 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
