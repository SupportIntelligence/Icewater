import "hash"

rule n3ed_51996b64d99bd932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.51996b64d99bd932"
     cluster="n3ed.51996b64d99bd932"
     cluster_size="24 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['0db9811a5573b5367e458347aa073ad2', '879cac19d352c2416c0e4dbc20837815', '345fd0fda66f3a96408aeff3bbd19edd']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(340992,1024) == "dd91d06741e0bcecc34711b0e573b5c3"
}

