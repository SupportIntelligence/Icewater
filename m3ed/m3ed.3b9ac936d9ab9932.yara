import "hash"

rule m3ed_3b9ac936d9ab9932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.3b9ac936d9ab9932"
     cluster="m3ed.3b9ac936d9ab9932"
     cluster_size="7 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['dd912820af9a6d67ab69e24588dbb537', 'd5c22488802bb72fe0505fd029d892f7', 'c69350b5bce3b3de96ffbe5b8bed618f']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(73728,1024) == "d8b3e446ad7fc1eeab8a639744aaa5fd"
}

