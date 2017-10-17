import "hash"

rule k3e9_6b64d34f8b4b5912
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6b64d34f8b4b5912"
     cluster="k3e9.6b64d34f8b4b5912"
     cluster_size="573 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob patched"
     md5_hashes="['a3f1c7f4ed86178f58787d7dfe68ca33', 'c6a6e4091101c3bbd8b5afe048e192df', 'c11282476a711eabc85a402920527fb6']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(18612,1036) == "6b61b0cff428f017f29ce22ade6c00dd"
}

