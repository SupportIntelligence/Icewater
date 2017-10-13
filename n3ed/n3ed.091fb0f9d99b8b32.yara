import "hash"

rule n3ed_091fb0f9d99b8b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.091fb0f9d99b8b32"
     cluster="n3ed.091fb0f9d99b8b32"
     cluster_size="380 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['c73cd8b211dd92b11888221a0c1c8364', 'c40e9c79584ea42815d2a041cf0e4f53', '3f52de02a6df7e6fd4269bcd29920f72']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(546051,1047) == "5238f707ac5ac25c6a9c24fe96b13a54"
}

