
rule n3ed_591385a7be631b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.591385a7be631b32"
     cluster="n3ed.591385a7be631b32"
     cluster_size="193"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['0b9ee56897e4c24b53a6cf79c2ae71b8','10e635cdb083711e4e9d430e55827628','31856f7c7df9b450d49a9d695701af07']"

   strings:
      $hex_string = { 4d083bcb7c062bcbd3e8eb288a1688550b4633d22bd98a4d0b570fb6f9c1ef0703c00bc702c942f6c20774048a0e46424b75e75f5e5b5dc3568bf18b461085c0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
