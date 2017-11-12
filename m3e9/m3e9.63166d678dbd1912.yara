
rule m3e9_63166d678dbd1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.63166d678dbd1912"
     cluster="m3e9.63166d678dbd1912"
     cluster_size="65"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['040b091931b9b4f7d168589e5d9f4a87','07ef54def640b4d64e308f3106071add','a3da081286d0ad3e40deca9d95a0cf2b']"

   strings:
      $hex_string = { a04e3c59bb3604a90111239d3d1815d640ebae49ec0c4c26b045a9e4f1be8c5d6a9ebd6cac3e6c869045d65e5bbc1f1f839ce8bd65b39c663005d13b983e4ce4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
