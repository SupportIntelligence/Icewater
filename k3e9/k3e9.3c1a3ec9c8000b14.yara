import "hash"

rule k3e9_3c1a3ec9c8000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1a3ec9c8000b14"
     cluster="k3e9.3c1a3ec9c8000b14"
     cluster_size="76 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170811"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['a42c1162037493049ef7e888acb7f6b9', 'a4c3825738c22dd282b82904ad0b46f3', 'f67ad4ba52d5c65ee4df6c38070330e7']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

