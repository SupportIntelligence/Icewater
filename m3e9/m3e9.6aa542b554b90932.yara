import "hash"

rule m3e9_6aa542b554b90932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6aa542b554b90932"
     cluster="m3e9.6aa542b554b90932"
     cluster_size="70 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170831"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="shipup razy gepys"
     md5_hashes="['be55974ef84c12c4ad3a235ff2b0b52b', 'ab1cceb0d441f2acb3a1c9f601e8339b', 'b5500ddea8bdf3b55e17acebaeb2f16b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(166400,1024) == "389e5f153b9573771a6b11e72b215879"
}

