import "hash"

rule k3e9_6b64d34f896b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f896b5912"
     cluster="k3e9.6b64d34f896b5912"
     cluster_size="57 samples"
     yaraexchange = "No distribution without author's consent"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170812"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['ba31270c8beef26a03e7d8551bf6ff0c', 'b0337b0823e344c30e1654b3049ae389', '3c41b69e94fb3ab31ba15a533a6d862c']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(24828,1036) == "b430fb8cdfb0eaa02d3e9c2620da748a"
}

