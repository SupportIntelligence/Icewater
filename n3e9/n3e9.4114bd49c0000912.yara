import "hash"

rule n3e9_4114bd49c0000912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4114bd49c0000912"
     cluster="n3e9.4114bd49c0000912"
     cluster_size="295 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vobfus sirefef jorik"
     md5_hashes="['a658806cc2c23286662b73ef89b760e1', 'ed286d0e4b4409850c502d3b4e108a29', '2ad90d0154b42023835d1de234af0c6f']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(221184,1024) == "63c9211d03f153398b07df0f5c030d86"
}

