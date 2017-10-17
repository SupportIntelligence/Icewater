import "hash"

rule k3e9_232ca619ca9a9932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.232ca619ca9a9932"
     cluster="k3e9.232ca619ca9a9932"
     cluster_size="5 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="qukart berbew backdoor"
     md5_hashes="['98ec2401a3bfeebc3e69143a42aa84fc', '1653e1f167d90c36fe788bb3c391093a', '98ec2401a3bfeebc3e69143a42aa84fc']"


   condition:
      filesize > 16384 and filesize < 65536
      and hash.md5(49091,1249) == "d06857e133fd37b7cc5535176ea36368"
}

