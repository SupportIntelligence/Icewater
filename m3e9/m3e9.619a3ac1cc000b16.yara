import "hash"

rule m3e9_619a3ac1cc000b16
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.619a3ac1cc000b16"
     cluster="m3e9.619a3ac1cc000b16"
     cluster_size="40 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="allaple rahack backdoor"
     md5_hashes="['a68e85ab90bf2d3ae9ad88f10e45c899', 'baa7df1d0724067deef6ee1fa65dd0d3', '5290696c205d36db8b8123a1bd4dea60']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(62976,1024) == "38345c2f0e0fb848e12408e6736482bc"
}

