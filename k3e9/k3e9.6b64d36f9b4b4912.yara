import "hash"

rule k3e9_6b64d36f9b4b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36f9b4b4912"
     cluster="k3e9.6b64d36f9b4b4912"
     cluster_size="11 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['d09f221bef35545fcd0369c3ef2e5166', '888c9693fb2ea9e9708e12e093e24bbf', 'dd90731de183bb258bf6f4e4c968f67f']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(7216,1036) == "27a10cb18182bb90bc5569da36fb9e39"
}

