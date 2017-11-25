
rule n3ed_63161af996c31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.63161af996c31932"
     cluster="n3ed.63161af996c31932"
     cluster_size="121"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox yontoo graftor"
     md5_hashes="['03564529ba84e9861299b4a5ba24b970','03d7d15b9cfc936cf2301695dd15e73b','27eab23021bd00bd7a29452f71352118']"

   strings:
      $hex_string = { 04020000696d756c0000000000000000000000000041050700210407002106120000000000840000000000000000000000000000020000000108000070757368 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
