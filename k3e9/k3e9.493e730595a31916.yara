import "hash"

rule k3e9_493e730595a31916
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.493e730595a31916"
     cluster="k3e9.493e730595a31916"
     cluster_size="8 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['3c0b528b1cab23127480af61d521c3e9', '2e9b2562f45531700a98d76f0fda67a1', '2e9b2562f45531700a98d76f0fda67a1']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(15872,1024) == "2be0f6e1890b843287e156fe1877e9d8"
}

