import "hash"

rule n3f0_4b192a49c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.4b192a49c0000b12"
     cluster="n3f0.4b192a49c0000b12"
     cluster_size="251 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="midie mira krap"
     md5_hashes="['b92bdf700dfbaa8fc4fd69f87f49212b', 'a08a36cf0c1bab33ce69c27e50a68547', 'd891d8cf5ec62f0424a921dedc31e5af']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(214016,1024) == "944d75c5e6743f11311bb7111b911cac"
}

