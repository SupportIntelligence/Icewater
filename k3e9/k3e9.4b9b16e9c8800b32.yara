import "hash"

rule k3e9_4b9b16e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4b9b16e9c8800b32"
     cluster="k3e9.4b9b16e9c8800b32"
     cluster_size="17043 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="bavs trojandownloader upatre"
     md5_hashes="['09ec221f2f68464dbf9996cc0e0bb558', '0729f63545732cd537d818952d682fb0', '122808fb432f3e2c01d0277522699cb8']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(16054,1054) == "c6c893a0229a295473f1d2e717196e00"
}

