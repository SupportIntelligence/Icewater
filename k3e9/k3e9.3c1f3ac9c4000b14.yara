import "hash"

rule k3e9_3c1f3ac9c4000b14
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3c1f3ac9c4000b14"
     cluster="k3e9.3c1f3ac9c4000b14"
     cluster_size="117 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170816"
     license = "non-commercial use only"
     family="razy simbot backdoor"
     md5_hashes="['f2e9e518decc02214eb8812328eaf184', '570d97dcfa962ff020516750db095257', 'b1275a2251455b82514bef6954c723a1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(5632,1536) == "b09e1f7c28fc22c6f6859d92fabdae15"
}

