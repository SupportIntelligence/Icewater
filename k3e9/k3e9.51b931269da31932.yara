import "hash"

rule k3e9_51b931269da31932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.51b931269da31932"
     cluster="k3e9.51b931269da31932"
     cluster_size="360 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['d2882784535c6a05cdce7c34032cc897', 'bf18cd3eb77cda90f3af515a10e965b9', 'af551dacd620f9ab5bfbdd10da261e39']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(20480,1024) == "a2c8c0039854981798c6825d650e8979"
}

