import "hash"

rule n3f9_4994b298ca210b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f9.4994b298ca210b32"
     cluster="n3f9.4994b298ca210b32"
     cluster_size="2017 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="zusy qqpass scar"
     md5_hashes="['19aa2371d11dd25880ddd442dacf24f1', '178857c91e0155230c02dda58c01c653', '10d2113fb2fcf18dc4b8ef6c0ec840a1']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(583680,1024) == "a91e2e956708fc174bf8f93c9e3b170a"
}

