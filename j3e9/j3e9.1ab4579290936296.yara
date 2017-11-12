import "hash"

rule j3e9_1ab4579290936296
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.1ab4579290936296"
     cluster="j3e9.1ab4579290936296"
     cluster_size="870"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171105"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zbot upatre generickd"
     md5_hashes="['01d884ae003792202ea5b4a3496a9a6d','047edc4ca320255504b3060d94315652','16ad908714aec41e03fbad2f5e54880e']"


   condition:
      
      filesize > 16384 and filesize < 65536
      and hash.md5(4096,4096) == "e20406493414569b1d4da833bb0c6dbc"
}

