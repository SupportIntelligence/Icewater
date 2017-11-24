
rule o3e9_29946995ca230b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.29946995ca230b12"
     cluster="o3e9.29946995ca230b12"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr unwanted"
     md5_hashes="['186ca73e0c70159149c7a33bcfb9954a','43d4c4edb0f686d36aa6a6afa3068b29','fe2f525f575d88d51b55c99cd9ddd088']"

   strings:
      $hex_string = { 752e52b13b82e8a908aeec808ae198965f8bde395c64cfee6bc9e9b528e263c87451057369e746d1815e48ce1761f60e377b226a1844c4a77f67d94b3301e4b6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
