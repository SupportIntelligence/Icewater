import "hash"

rule m3ec_169b1cc9cc000922
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.169b1cc9cc000922"
     cluster="m3ec.169b1cc9cc000922"
     cluster_size="18622 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="kazy hupigon kryptik"
     md5_hashes="['07e1855cd98732d41af2fcb8db65ff5f', '095baa5d0e6188497da6a3e1e1d73c40', '09cd8c23db3144b62aa8ea0a38ba6433']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(5120,1024) == "a4e924d28715e25a56b8ddfeff689404"
}

