import "hash"

rule k3e9_4da0d6d348001112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4da0d6d348001112"
     cluster="k3e9.4da0d6d348001112"
     cluster_size="10185 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="upatre cryptolocker waski"
     md5_hashes="['193952d04ac2b6a66f26db1e4ccab624', '0441f2c69f3719447261e666193a9d10', '0efc4d49c1e94a9d5106b51509f987d6']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20312,1066) == "62351412a0203bf192189e6dff441833"
}

