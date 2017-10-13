import "hash"

rule k3e9_4da0d6d348001112
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4da0d6d348001112"
     cluster="k3e9.4da0d6d348001112"
     cluster_size="3358 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="upatre cryptolocker waski"
     md5_hashes="['290bdbc436d20bafbf85feebe925b5ad', '1eca06d39bf71b7c9411af88532effaf', '164ffa407d741e649461195c619bb2bb']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20312,1066) == "62351412a0203bf192189e6dff441833"
}

