import "hash"

rule n3ed_15f0dde1c2000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.15f0dde1c2000912"
     cluster="n3ed.15f0dde1c2000912"
     cluster_size="4 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['4fdfcd42e454ecc2740d11d69af2eb46', 'a350fe37cebed413f25de49cf754da48', 'a350fe37cebed413f25de49cf754da48']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(175616,1024) == "7858e5bdec228257b0fded716f7e177d"
}

