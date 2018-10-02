
rule n26bb_1b9d6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.1b9d6a48c0000b12"
     cluster="n26bb.1b9d6a48c0000b12"
     cluster_size="157"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kazy malicious dtja"
     md5_hashes="['61089dee749834fa61a0f22d628fb27fc786b3f9','5f907aad52f3f08835da723dab1cab14331a7023','fa7211db8b1d0b1f9f37bbce9f7bbe2786afe2c9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.1b9d6a48c0000b12"

   strings:
      $hex_string = { 36453bae83b807ab982aa1fbe595e219b0d8118d868f14be0932fec2965d695a232c0526ed1627009368c1ef9c8b3c409b910c34baebaa3d5779a0f2a3d9528c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
