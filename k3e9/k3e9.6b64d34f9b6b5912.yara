import "hash"

rule k3e9_6b64d34f9b6b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f9b6b5912"
     cluster="k3e9.6b64d34f9b6b5912"
     cluster_size="270 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="virut virtob patched"
     md5_hashes="['734893fa32631513d2a582f6d426e327', 'b26946e1e2f9ee9b840d2a63f970a9fd', 'b776eca4637da5551a03f32af6bf5948']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(8192,256) == "b36bd97e697e1a8c585291e6cbcffcf4"
}

