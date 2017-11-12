import "hash"

rule o3e9_0b9269d29c92f9f2
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.0b9269d29c92f9f2"
     cluster="o3e9.0b9269d29c92f9f2"
     cluster_size="709 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="installmonster bundler dlboost"
     md5_hashes="['0f9a2ddd0986f706c3f621000c10161b', '642581344e3574589f58b7995c4dac0d', '6b8af8bd0646fea718248ee86668c8ee']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(1358336,1024) == "63be563370ec13e01afd1b37757420f6"
}

