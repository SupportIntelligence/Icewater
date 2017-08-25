import "hash"

rule k3e9_6b64d36f9b4b4912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d36f9b4b4912"
     cluster="k3e9.6b64d36f9b4b4912"
     cluster_size="9 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170815"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['888c9693fb2ea9e9708e12e093e24bbf', 'be06a22fc2046101545f242c97b12879', '0fdde7073d975d51106439431120a2d4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(7216,1036) == "27a10cb18182bb90bc5569da36fb9e39"
}

