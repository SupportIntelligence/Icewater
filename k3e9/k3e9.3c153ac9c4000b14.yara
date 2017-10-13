import "hash"

rule k3e9_3c153ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c153ac9c4000b14"
     cluster="k3e9.3c153ac9c4000b14"
     cluster_size="483 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['670bfcad64499a9f3749f0eab05d419d', '115ccdb35a1a8141877d315c72a1dc4f', 'b3340ffe62d39fcd23f09d4704f6c3de']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

