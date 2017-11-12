import "hash"

rule k3e9_6a928299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a928299c2200b12"
     cluster="k3e9.6a928299c2200b12"
     cluster_size="50257 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="androm downloadguide ocna"
     md5_hashes="['017714ee48f9d80139bdc067b7cb76d2', '00805f8db532aca8bd4c8256720471f9', '00de4937aad32fecef9df5ad3106f43d']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(29696,1024) == "38aeb4bc65f49fd634cc19a8c816016c"
}

