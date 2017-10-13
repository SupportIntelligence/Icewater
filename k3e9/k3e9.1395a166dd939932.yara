import "hash"

rule k3e9_1395a166dd939932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1395a166dd939932"
     cluster="k3e9.1395a166dd939932"
     cluster_size="157 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20170825"
     license = "non-commercial use only"
     family="virut virtob virux"
     md5_hashes="['cdf1c8d113e8c04f3e1ecd8a3b228dd0', 'c45e68f5b9501441d112237f21075ea4', '7a524ed3408c0a7e5ae9ab26f52f2e72']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(27648,1024) == "fb2c6e74a20f6c3f6c3d6d8b4b1542e9"
}

