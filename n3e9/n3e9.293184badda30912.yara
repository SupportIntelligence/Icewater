
rule n3e9_293184badda30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.293184badda30912"
     cluster="n3e9.293184badda30912"
     cluster_size="7"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['7912ec8cdea84298ee9f26e0543de926','7b409f21ae7985650c20865bf3dcfa28','ef352127fd207f5583282f4053050d0e']"

   strings:
      $hex_string = { ce5da795ee66b441786098db0489a2208cac47100956ca2b87da0811e2b89c3cd102e9925823abea704d7a1b811deb8e22b7b06c15cd21ec79f01cc59edf7ec7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
