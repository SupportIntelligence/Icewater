import "hash"

rule m3e9_251526cfc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.251526cfc6220b12"
     cluster="m3e9.251526cfc6220b12"
     cluster_size="944 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="vobfus zusy uouh"
     md5_hashes="['07595a47414f262a4752aead57ebda0a', '566abf3a009fd27a9694977d8153335f', '26559987cb53a100f136de0d66c54447']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(119808,1024) == "7980f218ddc7e003b4787e4f217584a0"
}

