import "hash"

rule k3e9_3c1a3ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1a3ac9c4000b14"
     cluster="k3e9.3c1a3ac9c4000b14"
     cluster_size="2432 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['59aa15d4c7fb164fe41ed9b049029275', '5248c0bb065c777c992c97652008ec11', '1d2b2f529d2f87d211a7f7c4cb66cbba']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

