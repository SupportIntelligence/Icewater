import "hash"

rule n3ed_51996b44d9eb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.51996b44d9eb1932"
     cluster="n3ed.51996b44d9eb1932"
     cluster_size="178 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['4159d7a205022d2cef286dbd4c789d06', '69d67539ab31e8abbfbac4b8cdc2dbad', '65f03a1b466c1e4ebe5bfe6e5a00f448']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(340992,1024) == "dd91d06741e0bcecc34711b0e573b5c3"
}

