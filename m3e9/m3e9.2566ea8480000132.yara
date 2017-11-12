import "hash"

rule m3e9_2566ea8480000132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.2566ea8480000132"
     cluster="m3e9.2566ea8480000132"
     cluster_size="125 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre kryptik trojandownloader"
     md5_hashes="['657e90bf9da24ad22f4fbbc82aa5b083', 'e6af2df342db4a4e5386400d2b6dde95', 'bf485e63167be4f0c0da35405562dade']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(50688,1024) == "59a43904558e996a765ce463ec38db9a"
}

