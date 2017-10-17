import "hash"

rule m3e9_59a24c63519646d2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.59a24c63519646d2"
     cluster="m3e9.59a24c63519646d2"
     cluster_size="57 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef malicious"
     md5_hashes="['aba201f3a51ef9cee9cb01a91931dfe0', 'bf3afeac37df4cb1355bc05ced21085f', '8d401067398c1c8fff3680d7e7fd5864']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(147456,1024) == "d8717e07292784ddd3a6fc16c4a75afa"
}

