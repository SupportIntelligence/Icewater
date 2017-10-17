import "hash"

rule m3e9_5296d289a6210b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5296d289a6210b12"
     cluster="m3e9.5296d289a6210b12"
     cluster_size="1632 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="vbkrypt vobfus wbna"
     md5_hashes="['6b2724dfd5abb108689b83f196d768fd', '17b925af05d0309032ba0f69d925d3c1', '837165097eddac31cd56705abe7a6c7b']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(64512,1024) == "eb0b285a22454738a4b149354eced8c6"
}

