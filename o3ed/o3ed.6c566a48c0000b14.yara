import "hash"

rule o3ed_6c566a48c0000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.6c566a48c0000b14"
     cluster="o3ed.6c566a48c0000b14"
     cluster_size="6 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul malicious"
     md5_hashes="['1a451c85433115fbf8752c492814eaca', '1a451c85433115fbf8752c492814eaca', 'ad6f88d9b3c44c9af532b8abb30f5563']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(340992,1024) == "dd91d06741e0bcecc34711b0e573b5c3"
}

