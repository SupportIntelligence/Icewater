import "hash"

rule m3e9_6d14dee9c6000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6d14dee9c6000b12"
     cluster="m3e9.6d14dee9c6000b12"
     cluster_size="682 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="symmi swisyn abzf"
     md5_hashes="['850908db9ec6920a0d08ff24963fb2ac', '9b5d748f841a46309d93acd5ad6f570e', '17db21408e81bbb31abe2803fd8ce64c']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(8192,1024) == "9f712feaffef3b90b4425924542b4546"
}

