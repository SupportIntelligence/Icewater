import "hash"

rule m3e9_611a3ac1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.611a3ac1cc000b12"
     cluster="m3e9.611a3ac1cc000b12"
     cluster_size="1372 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple rahack backdoor"
     md5_hashes="['3a3f9bb8505454fc5f6a72eb7598f310', '73abb97ff677643e8f540fce06704e7e', '0b9df10609a74bee41b220e69238fae0']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62976,1024) == "38345c2f0e0fb848e12408e6736482bc"
}

