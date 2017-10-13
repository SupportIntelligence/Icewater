import "hash"

rule n3ed_51996b46dee31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.51996b46dee31932"
     cluster="n3ed.51996b46dee31932"
     cluster_size="339 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="ramnit nimnul bmnup"
     md5_hashes="['712ff9e1f2787fa1a643f5759198cdb1', 'd53b39a6c1ea1f1e15dea6342e52b031', 'da626c0f0a36c76176118a80a836f964']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(340992,1024) == "dd91d06741e0bcecc34711b0e573b5c3"
}

