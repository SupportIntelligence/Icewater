import "hash"

rule m3e9_785455a0a217eb4e
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.785455a0a217eb4e"
     cluster="m3e9.785455a0a217eb4e"
     cluster_size="99 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus barys diple"
     md5_hashes="['663a73c30facccd0dae1273be1f43e5f', 'abae69c9765e8f542dbd08a7e6250f9d', 'e3d3f2a1c641b0fb13970c22908cf3a4']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(235520,1024) == "383e01adaf7caed4677fa97941e8ffa1"
}

