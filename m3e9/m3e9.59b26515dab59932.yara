import "hash"

rule m3e9_59b26515dab59932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.59b26515dab59932"
     cluster="m3e9.59b26515dab59932"
     cluster_size="231 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="barys zbot jorik"
     md5_hashes="['a1c03ac148fa1d36205a8b2923bd4b42', 'dba5ecb50e3698b20d7fc10cc8e5a3d4', 'dbe83584ba601646ea46f5eb3c0692bc']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(195072,1536) == "37d1bc4959e128f0213c322d110c213b"
}

