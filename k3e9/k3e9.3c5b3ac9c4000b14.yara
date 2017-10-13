import "hash"

rule k3e9_3c5b3ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c5b3ac9c4000b14"
     cluster="k3e9.3c5b3ac9c4000b14"
     cluster_size="443 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['1bf1c8cd5977fce4b605b0a1a93bfaac', '9b8ca8a04732d0e8dc71cfeac95ea08f', 'a046efc37dbbb32217a9c343b37c3a5b']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

