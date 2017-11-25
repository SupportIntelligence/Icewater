
rule n3ed_633c3e916a001932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.633c3e916a001932"
     cluster="n3ed.633c3e916a001932"
     cluster_size="167"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox yontoo unwanted"
     md5_hashes="['04048b174e316f65c3a87b9f027bb755','0459f519d5cd0d8e68ed150cad40a2c8','1d9dd65bc1108bb7660d54c1e06ca084']"

   strings:
      $hex_string = { 02006675636f6d69700000000000000000003020000031200000000000000000000000d0800740000000000000000000000006000000050002006675636f6d69 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
