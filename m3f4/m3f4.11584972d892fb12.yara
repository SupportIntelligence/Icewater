import "hash"

rule m3f4_11584972d892fb12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f4.11584972d892fb12"
     cluster="m3f4.11584972d892fb12"
     cluster_size="828 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="backdoor nanocore noancooe"
     md5_hashes="['bb5bd47aaecbe69b95f7fdef576ed1bb', '319e2ddc7117c75eb848cf636c51f364', 'ccf57ea45bb47e5d39d7aa55cd60d546']"


   condition:
      filesize > 65536 and filesize < 262144
      and hash.md5(99840,1024) == "b7b7780a7488ec74afdab839017db84b"
}

