import "hash"

rule k3e9_3c5a3ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c5a3ac9c4000b14"
     cluster="k3e9.3c5a3ac9c4000b14"
     cluster_size="585 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['a5d678733db64978df24bbfbbca89b49', 'aec3ca9300723515005d590f3bf2ddb4', '24c8e4ef7ce42b710f7db808b4380ff4']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

